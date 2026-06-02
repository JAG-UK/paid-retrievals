package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/fidlabs/paid-retrievals/internal/pieceurls"
)

// makeProbeLog returns a pieceurls probe logger for --verbose mode only.
func makeProbeLog(stdout io.Writer, verbose bool) func(string, ...any) {
	if !verbose {
		return nil
	}
	return func(format string, args ...any) {
		if probeLogToStdout(format) {
			fmt.Fprintf(stdout, "    %s\n", fmt.Sprintf(format, args...))
		}
	}
}

func probeLogToStdout(format string) bool {
	// Keep bulky challenge dumps off verbose output.
	switch {
	case strings.HasPrefix(format, "challenge response body"),
		strings.HasPrefix(format, "challenge response headers"):
		return false
	default:
		return true
	}
}

// probeUIAdapter maps pieceurls probe callbacks to CLI progress spinners.
type probeUIAdapter struct {
	ui         ProgressUI
	pieceIdx   int
	pieceTotal int
}

func (a *probeUIAdapter) ProbeStart(pieceCID string, endpointCount int) {
	a.ui.ProbeEndpointsStart(a.pieceIdx, a.pieceTotal, pieceCID, endpointCount)
}

func (a *probeUIAdapter) ProbeFinished(pieceCID string, completed, total int) {
	a.ui.ProbeEndpointsProgress(a.pieceIdx, a.pieceTotal, pieceCID, completed, total)
}

func probeCallbackFor(ui ProgressUI, pieceIdx, pieceTotal int) pieceurls.ProbeCallback {
	if !ui.Enabled() {
		return nil
	}
	return &probeUIAdapter{ui: ui, pieceIdx: pieceIdx, pieceTotal: pieceTotal}
}

func probeSelectionSummary(sel *pieceurls.Selection) string {
	if sel == nil || sel.Base == nil {
		return ""
	}
	if sel.Free {
		return fmt.Sprintf("free direct from %s (download after confirm)", sel.Base.String())
	}
	line := fmt.Sprintf("paid %s USDFC from %s", sel.PriceUSDFC, sel.Base.String())
	if p := strings.TrimSpace(sel.Payee0x); p != "" {
		line += fmt.Sprintf(" payee=%s", p)
	}
	return line
}
