package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/pieceurls"
)

var (
	downloadMaxAttempts   = 100
	downloadRetryDelay    = 500 * time.Millisecond
	downloadMaxRetrySleep = 30 * time.Minute
)

type retryableDownloadError struct {
	err         error
	writtenByte int64
}

func (e *retryableDownloadError) Error() string { return e.err.Error() }
func (e *retryableDownloadError) Unwrap() error { return e.err }

func downloadCAR(cli *http.Client, base *url.URL, cid, piecePath, client0x, authorization, outDir string, expectedTotal int64, ui ProgressUI, verbose bool) error {
	u := *base
	u.Path = piecePath
	if strings.TrimSpace(client0x) != "" {
		q := u.Query()
		q.Set("client", client0x)
		u.RawQuery = q.Encode()
	}
	fullURL := u.String()
	if verbose {
		if authorization != "" {
			payClientLog("paid GET %s (Authorization: Payment len=%d)", fullURL, len(authorization))
		} else {
			payClientLog("free GET %s", fullURL)
		}
	}
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return err
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	outPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
	partialPath := outPath + ".partial"
	paid := authorization != ""
	var resumeFrom int64
	var lastErr error
	var retrySleep time.Duration
	if ui.Enabled() {
		ui.DownloadStart(cid, fullURL, expectedTotal, paid, 0)
	}
	for attempt := 1; attempt <= downloadMaxAttempts; attempt++ {
		if ui.Enabled() {
			if attempt > 1 {
				ui.DownloadAttempt(expectedTotal, attempt-1)
			}
		} else if attempt > 1 && lastErr != nil {
			fmt.Fprintf(os.Stderr, "warning: retrying GET %s (%d/%d): %v\n", shortCID(cid), attempt, downloadMaxAttempts, lastErr)
		}
		attemptReq := req.Clone(req.Context())
		// Be explicit per attempt in case intermediaries/request cloning behavior changes.
		if authorization != "" {
			attemptReq.Header.Set("Authorization", authorization)
		}
		if resumeFrom > 0 {
			attemptReq.Header.Set("Range", fmt.Sprintf("bytes=%d-", resumeFrom))
			if verbose {
				payClientLog("GET %s retry with Range: bytes=%d-", shortCID(cid), resumeFrom)
			}
		}
		lastErr = downloadCAROnce(cli, attemptReq, cid, outDir, expectedTotal, resumeFrom, ui, verbose)
		if lastErr == nil {
			return nil
		}
		if retryable, ok := errors.AsType[*retryableDownloadError](lastErr); ok {
			resumeFrom = retryable.writtenByte
		}
		if !isRetryableDownloadError(lastErr) || attempt == downloadMaxAttempts {
			break
		}
		delay := downloadRetryDelay * time.Duration(attempt)
		if retrySleep+delay > downloadMaxRetrySleep {
			break
		}
		time.Sleep(delay)
		retrySleep += delay
	}
	if ui.Enabled() {
		ui.DownloadFailed(cid)
	}
	_ = os.Remove(partialPath)
	return lastErr
}

func downloadCAROnce(cli *http.Client, req *http.Request, cid, outDir string, expectedTotal, resumeFrom int64, ui ProgressUI, verbose bool) error {
	res, err := cli.Do(req)
	if err != nil {
		return &retryableDownloadError{err: err, writtenByte: resumeFrom}
	}
	defer res.Body.Close()
	if verbose {
		payClientLog("GET response status=%d for cid=%s", res.StatusCode, cid)
	}
	if resumeFrom > 0 && res.StatusCode != http.StatusPartialContent && res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if verbose {
			payClientLog("GET error body (truncated): %s", truncateForLog(string(b), 512))
		}
		if res.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			return fmt.Errorf("download %s failed: %s (range resume from %s)", cid, res.Status, formatBytes(resumeFrom))
		}
		return fmt.Errorf("download %s failed: %s %s", cid, res.Status, strings.TrimSpace(string(b)))
	}
	if resumeFrom == 0 && res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if verbose {
			payClientLog("GET error body (truncated): %s", truncateForLog(string(b), 512))
		}
		trimmed := strings.TrimSpace(string(b))
		var pd problemDetails
		if err := json.Unmarshal(b, &pd); err == nil && pd.Type != "" {
			msg := fmt.Sprintf("download %s failed: %s", cid, res.Status)
			if pd.Title != "" {
				msg += " - " + pd.Title
			}
			if pd.Detail != "" {
				msg += ": " + pd.Detail
			}
			msg += fmt.Sprintf(" (type=%s)", pd.Type)
			return errors.New(msg)
		}
		return fmt.Errorf("download %s failed: %s %s", cid, res.Status, trimmed)
	}

	outPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
	partialPath := outPath + ".partial"
	total := expectedTotal
	if respTotal := pieceurls.ResponseTotalBytes(res); respTotal >= 0 {
		if resumeFrom > 0 && res.StatusCode == http.StatusPartialContent {
			total = resumeFrom + respTotal
		} else {
			total = respTotal
		}
	}
	if ui.Enabled() {
		ui.DownloadHeaders(cid, total)
		if resumeFrom > 0 {
			ui.DownloadProgress(cid, resumeFrom, total)
		}
	}

	openFlags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if resumeFrom > 0 && res.StatusCode == http.StatusPartialContent {
		if verbose {
			payClientLog("GET %s resumed at %s (206 Partial Content)", shortCID(cid), formatBytes(resumeFrom))
		}
		openFlags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	} else if resumeFrom > 0 && res.StatusCode == http.StatusOK {
		// Upstream ignored Range; restart from scratch on this attempt.
		if verbose {
			payClientLog("GET %s ignored Range; restarting from 0 (200 OK)", shortCID(cid))
		}
		resumeFrom = 0
	}
	f, err := os.OpenFile(partialPath, openFlags, 0o644)
	if err != nil {
		return err
	}
	written, copyErr := copyWithProgress(f, res.Body, cid, total, resumeFrom, ui)
	closeErr := f.Close()
	if copyErr != nil {
		return &retryableDownloadError{
			err:         fmt.Errorf("download %s: %w (%s written)", cid, copyErr, formatBytes(written)),
			writtenByte: written,
		}
	}
	if closeErr != nil {
		_ = os.Remove(partialPath)
		return closeErr
	}
	if getShortOfExpectedSize(written, total) {
		if !ui.Enabled() {
			warnGETShortOfExpected(cid, written, total)
		}
		return &retryableDownloadError{
			err:         fmt.Errorf("download %s incomplete: %s written, expected %s", cid, formatBytes(written), formatBytes(total)),
			writtenByte: written,
		}
	}
	if err := os.Rename(partialPath, outPath); err != nil {
		_ = os.Remove(partialPath)
		return err
	}
	if ui.Enabled() {
		ui.DownloadDone(cid, outPath)
	}
	return nil
}

// getShortOfExpectedSize reports whether the GET body ended before probe HEAD size.
func getShortOfExpectedSize(getWritten, probeHEADBytes int64) bool {
	return probeHEADBytes >= 0 && getWritten < probeHEADBytes
}

// warnGETShortOfExpected logs when progress UI is disabled (non-terminal stderr).
func warnGETShortOfExpected(cid string, getWritten, probeHEADBytes int64) {
	fmt.Fprintf(os.Stderr,
		"warning: GET %s short read (%s written, %s from probe HEAD); retrying file\n",
		shortCID(cid), formatBytes(getWritten), formatBytes(probeHEADBytes),
	)
}

func isRetryableDownloadError(err error) bool {
	if err == nil {
		return false
	}
	var retryable *retryableDownloadError
	return errors.As(err, &retryable)
}

func downloadFreeCAR(cli *http.Client, base *url.URL, cid, outDir string, expectedTotal int64, ui ProgressUI, verbose bool) error {
	u := *base
	piecePath := "/piece/" + cid
	u.Path = piecePath
	return downloadCAR(cli, &u, cid, piecePath, "", "", outDir, expectedTotal, ui, verbose)
}

func copyWithProgress(dst io.Writer, src io.Reader, cid string, total, initialWritten int64, ui ProgressUI) (int64, error) {
	if !ui.Enabled() {
		n, err := io.Copy(dst, src)
		return initialWritten + n, err
	}
	buf := make([]byte, 32*1024)
	written := initialWritten
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			wn, werr := dst.Write(buf[:n])
			written += int64(wn)
			if werr != nil {
				return written, werr
			}
			if wn != n {
				return written, io.ErrShortWrite
			}
			if ui.Enabled() {
				ui.DownloadProgress(cid, written, total)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				if ui.Enabled() && written > 0 {
					ui.DownloadProgress(cid, written, total)
				}
				return written, nil
			}
			return written, rerr
		}
	}
}
