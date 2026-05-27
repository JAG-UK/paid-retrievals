//go:build e2e_stack

package stack_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/fidlabs/paid-retrievals/test/e2e/harness"
)

var (
	moduleRoot string
	bins       harness.Binaries
)

func TestMain(m *testing.M) {
	root, err := harness.ModuleRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "module root: %v\n", err)
		os.Exit(1)
	}
	moduleRoot = root

	if harness.DockerAvailable() {
		dir, err := os.MkdirTemp("", "paid-retrievals-e2e-bin-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "mkdir temp: %v\n", err)
			os.Exit(1)
		}
		defer os.RemoveAll(dir)
		bins, err = harness.BuildBinaries(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "build binaries: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "e2e_stack: docker not available; stack tests will skip")
	}
	os.Exit(m.Run())
}
