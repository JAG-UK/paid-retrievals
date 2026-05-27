package harness

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Nginx runs an nginx container serving PieceCARBody at /piece/<any-cid>.
type Nginx struct {
	BaseURL       string // http://127.0.0.1:<port>
	Port          int
	ContainerName string
}

// StartNginx starts nginx:stable-alpine with a small CAR fixture on a free local port.
func StartNginx(t *testing.T, root string) *Nginx {
	t.Helper()
	if !DockerAvailable() {
		t.Skip("docker not available")
	}

	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	pieceDir := filepath.Join(work, "piece")
	if err := os.MkdirAll(pieceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pieceDir, "data.car"), PieceCARBody, 0o644); err != nil {
		t.Fatal(err)
	}

	confSrc := filepath.Join(FixturesDir(root), "nginx", "default.conf")
	confData, err := os.ReadFile(confSrc)
	if err != nil {
		t.Fatalf("read nginx config %s: %v", confSrc, err)
	}
	confPath := filepath.Join(work, "default.conf")
	if err := os.WriteFile(confPath, confData, 0o644); err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("paid-retrievals-e2e-nginx-%d", os.Getpid())
	_ = exec.Command("docker", "rm", "-f", name).Run()

	args := []string{
		"run", "-d",
		"--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:80", port),
		"-v", pieceDir + ":/usr/share/nginx/html/piece:ro",
		"-v", confPath + ":/etc/nginx/conf.d/default.conf:ro",
		"nginx:stable-alpine",
	}
	var stderr bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stderr = &stderr
	if out, err := cmd.Output(); err != nil {
		t.Fatalf("docker run nginx: %v\n%s%s", err, stderr.String(), out)
	}

	ng := &Nginx{
		BaseURL:       fmt.Sprintf("http://127.0.0.1:%d", port),
		Port:          port,
		ContainerName: name,
	}
	t.Cleanup(func() {
		c := exec.Command("docker", "rm", "-f", name)
		c.Stdout = nil
		c.Stderr = nil
		_ = c.Run()
	})

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	url := ng.BaseURL + "/piece/" + TestPieceCID
	for time.Now().Before(deadline) {
		res, err := client.Get(url)
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return ng
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("nginx not ready at %s", ng.BaseURL)
	return ng
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
