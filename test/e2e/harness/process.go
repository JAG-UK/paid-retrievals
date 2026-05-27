package harness

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// SPProxy runs sp-proxy as a subprocess.
type SPProxy struct {
	BaseURL string // http://127.0.0.1:<port>
	Port    int
	cmd     *exec.Cmd
	stderr  *bytes.Buffer
}

// SPProxyConfig configures a sp-proxy instance.
type SPProxyConfig struct {
	Bin          string
	ListenPort   int
	UpstreamPort int
	DBPath       string
	SPKeyFile    string
	PayRPCURL    string
	PriceUSDFC   string
	PayDebug     bool
}

// StartSPProxy launches sp-proxy and waits for /health.
func StartSPProxy(t *testing.T, cfg SPProxyConfig) *SPProxy {
	t.Helper()
	if cfg.Bin == "" {
		t.Fatal("sp-proxy binary path required")
	}
	if cfg.PayRPCURL == "" {
		cfg.PayRPCURL = DefaultCalibrationRPC
	}
	if cfg.PriceUSDFC == "" {
		cfg.PriceUSDFC = "0.01"
	}
	if cfg.ListenPort == 0 {
		var err error
		cfg.ListenPort, err = freeTCPPort()
		if err != nil {
			t.Fatal(err)
		}
	}
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(t.TempDir(), "sp-proxy.db")
	}

	var stderr bytes.Buffer
	args := []string{
		"--listen", fmt.Sprintf("127.0.0.1:%d", cfg.ListenPort),
		"--db", cfg.DBPath,
		"--price-usdfc", cfg.PriceUSDFC,
		"--upstream-host", "127.0.0.1",
		"--upstream-port", strconv.Itoa(cfg.UpstreamPort),
		"--pay-rpc-url", cfg.PayRPCURL,
		"--pay-private-key-file", cfg.SPKeyFile,
	}
	if cfg.PayDebug || DebugEnabled() {
		args = append(args, "--pay-debug")
	}
	cmd := exec.Command(cfg.Bin, args...)
	if DebugEnabled() {
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	} else {
		cmd.Stderr = &stderr
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sp-proxy: %v\n%s", err, stderr.String())
	}

	proxy := &SPProxy{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort),
		Port:    cfg.ListenPort,
		cmd:     cmd,
		stderr:  &stderr,
	}
	t.Cleanup(func() {
		if proxy.cmd.Process != nil {
			_ = proxy.cmd.Process.Kill()
		}
		_, _ = proxy.cmd.Process.Wait()
	})

	if err := waitHTTPOK(proxy.BaseURL+"/health", 45*time.Second); err != nil {
		t.Fatalf("sp-proxy health: %v\nstderr:\n%s", err, proxy.StderrTail())
	}
	return proxy
}

// StderrTail returns recent sp-proxy stderr for failures.
func (p *SPProxy) StderrTail() string {
	if p.stderr == nil {
		return ""
	}
	s := p.stderr.String()
	const max = 16 << 10
	if len(s) > max {
		return s[len(s)-max:]
	}
	return s
}

func waitHTTPOK(url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		res, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("status %d body %q", res.StatusCode, string(body))
		time.Sleep(300 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("timeout waiting for %s: %w", url, lastErr)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

// RunRetrievalClient runs the retrieval-client binary with args and optional stdin.
func RunRetrievalClient(t *testing.T, bin string, stdin string, extraEnv []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
	cmd.Env = append(cmd.Env, extraEnv...)
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}
	var outBuf, errBuf bytes.Buffer
	if DebugEnabled() {
		cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &errBuf)
	} else {
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
	}
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("run retrieval-client %v: %v", args, err)
		}
	}

	if DebugEnabled() {
		outStr := strings.TrimSpace(outBuf.String())
		if outStr != "" {
			t.Logf("[retrieval-client stdout]\n%s", outStr)
		}
		errStr := strings.TrimSpace(errBuf.String())
		if errStr != "" {
			t.Logf("[retrieval-client stderr]\n%s", errStr)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}
