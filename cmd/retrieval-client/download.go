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

	"github.com/fidlabs/paid-retrievals/internal/pieceurls"
)

func downloadCAR(cli *http.Client, base *url.URL, cid, piecePath, authorization, outDir string, expectedTotal int64, ui ProgressUI, payDebug bool) (string, error) {
	u := *base
	u.Path = piecePath
	fullURL := u.String()
	if payDebug {
		if authorization != "" {
			payClientLog("paid GET %s (Authorization: Payment len=%d)", fullURL, len(authorization))
		} else {
			payClientLog("free GET %s", fullURL)
		}
	}
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return "", err
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if ui.Enabled() {
		ui.DownloadStart(cid, fullURL, expectedTotal)
	}
	res, err := cli.Do(req)
	if err != nil {
		if ui.Enabled() {
			ui.DownloadFailed(cid)
		}
		return "", err
	}
	defer res.Body.Close()
	if payDebug {
		payClientLog("paid GET response status=%d for cid=%s", res.StatusCode, cid)
	}
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if payDebug {
			payClientLog("paid GET error body (truncated): %s", truncateForLog(string(b), 512))
		}
		trimmed := strings.TrimSpace(string(b))
		var pd problemDetails
		if err := json.Unmarshal(b, &pd); err == nil && pd.Type != "" {
			if ui.Enabled() {
				ui.DownloadFailed(cid)
			}
			msg := fmt.Sprintf("download %s failed: %s", cid, res.Status)
			if pd.Title != "" {
				msg += " - " + pd.Title
			}
			if pd.Detail != "" {
				msg += ": " + pd.Detail
			}
			msg += fmt.Sprintf(" (type=%s)", pd.Type)
			return "", errors.New(msg)
		}
		if ui.Enabled() {
			ui.DownloadFailed(cid)
		}
		return "", fmt.Errorf("download %s failed: %s %s", cid, res.Status, trimmed)
	}

	outPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
	partialPath := outPath + ".partial"
	total := expectedTotal
	if respTotal := pieceurls.ResponseTotalBytes(res); respTotal >= 0 {
		total = respTotal
	}
	if ui.Enabled() {
		ui.DownloadHeaders(cid, total)
	}
	f, err := os.Create(partialPath)
	if err != nil {
		if ui.Enabled() {
			ui.DownloadFailed(cid)
		}
		return "", err
	}
	written, copyErr := copyWithProgress(f, res.Body, cid, total, ui)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(partialPath)
		if ui.Enabled() {
			ui.DownloadFailed(cid)
		}
		return "", fmt.Errorf("download %s: %w (%s written)", cid, copyErr, formatBytes(written))
	}
	if closeErr != nil {
		_ = os.Remove(partialPath)
		if ui.Enabled() {
			ui.DownloadFailed(cid)
		}
		return "", closeErr
	}
	if err := os.Rename(partialPath, outPath); err != nil {
		_ = os.Remove(partialPath)
		if ui.Enabled() {
			ui.DownloadFailed(cid)
		}
		return "", err
	}
	if ui.Enabled() {
		ui.DownloadDone(cid, outPath)
	}
	return outPath, nil
}

func downloadFreeCAR(cli *http.Client, base *url.URL, cid, client0x, outDir string, expectedTotal int64, ui ProgressUI, payDebug bool) (string, error) {
	u := *base
	piecePath := "/piece/" + cid
	u.Path = piecePath
	q := u.Query()
	q.Set("client", client0x)
	u.RawQuery = q.Encode()
	return downloadCAR(cli, &u, cid, piecePath, "", outDir, expectedTotal, ui, payDebug)
}

func copyWithProgress(dst io.Writer, src io.Reader, cid string, total int64, ui ProgressUI) (int64, error) {
	if !ui.Enabled() {
		return io.Copy(dst, src)
	}
	buf := make([]byte, 32*1024)
	var written int64
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
