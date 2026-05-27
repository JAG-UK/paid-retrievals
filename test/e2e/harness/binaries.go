package harness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// BuildBinaries compiles retrieval-client and sp-proxy into dir unless env overrides are set.
func BuildBinaries(dir string) (Binaries, error) {
	out := Binaries{
		RetrievalClient: os.Getenv(EnvRetrievalClientBin),
		SPProxy:         os.Getenv(EnvSPProxyBin),
	}
	if out.RetrievalClient != "" && out.SPProxy != "" {
		if err := statBin(out.RetrievalClient); err != nil {
			return Binaries{}, err
		}
		if err := statBin(out.SPProxy); err != nil {
			return Binaries{}, err
		}
		return out, nil
	}

	root, err := ModuleRoot()
	if err != nil {
		return Binaries{}, err
	}
	if out.RetrievalClient == "" {
		out.RetrievalClient = filepath.Join(dir, "retrieval-client")
		if err := goBuild(root, out.RetrievalClient, "./cmd/retrieval-client"); err != nil {
			return Binaries{}, fmt.Errorf("build retrieval-client: %w", err)
		}
	} else if err := statBin(out.RetrievalClient); err != nil {
		return Binaries{}, err
	}
	if out.SPProxy == "" {
		out.SPProxy = filepath.Join(dir, "sp-proxy")
		if err := goBuild(root, out.SPProxy, "./cmd/sp-proxy"); err != nil {
			return Binaries{}, fmt.Errorf("build sp-proxy: %w", err)
		}
	} else if err := statBin(out.SPProxy); err != nil {
		return Binaries{}, err
	}
	return out, nil
}

func goBuild(root, out, pkg string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func statBin(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("binary %q: %w", path, err)
	}
	return nil
}
