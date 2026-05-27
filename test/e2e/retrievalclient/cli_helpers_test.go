package retrievalclient_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type cliResult struct {
	Stdout string
	Stderr string
	Exit   int
}

func runCLI(t *testing.T, stdin string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(retrievalClientBin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := cliResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if strings.TrimSpace(os.Getenv("E2E_DEBUG")) != "" {
		outStr := strings.TrimSpace(res.Stdout)
		if outStr != "" {
			t.Logf("[retrieval-client stdout]\n%s", outStr)
		}
		errStr := strings.TrimSpace(res.Stderr)
		if errStr != "" {
			t.Logf("[retrieval-client stderr]\n%s", errStr)
		}
	}
	if err == nil {
		return res
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.Exit = exitErr.ExitCode()
		return res
	}
	t.Fatalf("run %s: %v", strings.Join(args, " "), err)
	return res
}

func combinedOutput(res cliResult) string {
	return res.Stdout + res.Stderr
}
