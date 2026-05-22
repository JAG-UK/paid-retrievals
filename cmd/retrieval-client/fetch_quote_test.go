package main

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
)

func TestTableCID(t *testing.T) {
	short := "bafyshortcid"
	if got := tableCID(short); got != short {
		t.Fatalf("short CID unchanged: %q", got)
	}
	long := "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	got := tableCID(long)
	if !strings.Contains(got, "...") {
		t.Fatal(got)
	}
	if len(got) != len(long[:10])+3+len(long[len(long)-6:]) {
		t.Fatalf("unexpected width: %q len=%d", got, len(got))
	}
}

func TestQuoteColumnWidths(t *testing.T) {
	longCID := "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	const bigSize = 32 << 30
	items := []challengeItem{
		{CID: longCID, Free: false, PriceUSDFC: "0.01", TotalBytes: bigSize},
		{CID: "bafyshort", Free: true, TotalBytes: -1},
	}
	cidW, typeW, sizeW, priceW := quoteColumnWidths(items)
	if cidW < len(tableCID(longCID)) {
		t.Fatalf("cidW=%d too narrow for tableCID", cidW)
	}
	if typeW < 4 || priceW < len("0.01 USDFC") {
		t.Fatalf("typeW=%d priceW=%d", typeW, priceW)
	}
	wantSizeW := len(formatQuoteSize(bigSize))
	if sizeW < wantSizeW {
		t.Fatalf("sizeW=%d want >= %d (%q)", sizeW, wantSizeW, formatQuoteSize(bigSize))
	}
}

func TestFormatQuoteSize(t *testing.T) {
	if formatQuoteSize(-1) != "—" {
		t.Fatal("unknown size")
	}
	if formatQuoteSize(0) != "0 B" {
		t.Fatal(formatQuoteSize(0))
	}
	if formatQuoteSize(1<<30) != "1.0 GiB" {
		t.Fatal(formatQuoteSize(1 << 30))
	}
}

func TestCountPaidPayees(t *testing.T) {
	items := []challengeItem{
		{Free: true, Payee0x: "0xaaa"},
		{Free: false, Payee0x: "0xbbb"},
		{Free: false, Payee0x: "0xbbb"},
		{Free: false, Payee0x: " 0xccc "},
		{Free: false, Payee0x: ""},
	}
	if n := countPaidPayees(items); n != 2 {
		t.Fatalf("got %d payees", n)
	}
	if countPaidPayees(nil) != 0 {
		t.Fatal("nil items")
	}
}

func TestPrintFetchQuoteAlignsColumns(t *testing.T) {
	longCID := "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	items := []challengeItem{
		{
			CID: longCID, Free: false, PriceUSDFC: "0.01", TotalBytes: 32 << 30,
			Base: mustParseURL(t, "http://127.0.0.1:8787"),
		},
		{
			CID: "bafyshort2", Free: true, TotalBytes: -1,
			Base: mustParseURL(t, "http://192.168.1.2:9000"),
		},
	}
	var buf bytes.Buffer
	printFetchQuote(&buf, items, "0.01")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var header, rowPaid, rowFree string
	for _, line := range lines {
		if strings.Contains(line, "CID") && strings.Contains(line, "SIZE") && strings.Contains(line, "SOURCE") {
			header = strings.TrimPrefix(line, "  ")
		}
		if strings.Contains(line, "...") && strings.Contains(line, "paid") {
			rowPaid = strings.TrimPrefix(line, "  ")
		}
		if strings.Contains(line, "bafyshort2") {
			rowFree = strings.TrimPrefix(line, "  ")
		}
	}
	if header == "" || rowPaid == "" || rowFree == "" {
		t.Fatalf("missing header or rows:\n%s", buf.String())
	}
	assertColumnAligned(t, "TYPE", header, rowPaid, "paid")
	assertColumnAligned(t, "SIZE", header, rowPaid, "32.0 GiB")
	assertColumnAligned(t, "PRICE", header, rowPaid, "0.01 USDFC")
	assertColumnAligned(t, "TYPE", header, rowFree, "free")
	assertColumnAligned(t, "SIZE", header, rowFree, "—")
	if !strings.Contains(buf.String(), "Total: 0.01 USDFC for 1 paid piece(s); 1 free") {
		t.Fatalf("mixed footer:\n%s", buf.String())
	}
}

func TestPrintFetchQuoteFreeOnly(t *testing.T) {
	items := []challengeItem{
		{CID: "bafyfree1", Free: true, TotalBytes: 1024, Base: mustParseURL(t, "http://sp/")},
	}
	var buf bytes.Buffer
	printFetchQuote(&buf, items, "0")
	out := buf.String()
	if !strings.Contains(out, "1.0 KiB") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "All 1 piece(s) are free") {
		t.Fatal(out)
	}
	if strings.Contains(out, "Total:") {
		t.Fatal("paid total should not appear", out)
	}
}

func TestPrintFetchQuotePaidOnly(t *testing.T) {
	const cid = "bafypaid1"
	items := []challengeItem{
		{CID: cid, Free: false, PriceUSDFC: "1.5", TotalBytes: -1, Base: mustParseURL(t, "http://proxy/")},
	}
	var buf bytes.Buffer
	printFetchQuote(&buf, items, "1.5")
	out := buf.String()
	header := strings.TrimPrefix(quoteHeaderLine(out), "  ")
	row := strings.TrimPrefix(quoteRowContaining(out, cid), "  ")
	assertColumnAligned(t, "SIZE", header, row, "—")
	if !strings.Contains(out, "Total: 1.5 USDFC for 1 paid piece(s).") {
		t.Fatal(out)
	}
	if strings.Contains(out, "; 1 free") || strings.Contains(out, "; 2 free") {
		t.Fatal("free suffix should not appear", out)
	}
}

func assertColumnAligned(t *testing.T, col, header, row, value string) {
	t.Helper()
	colIdx := strings.Index(header, col)
	if colIdx < 0 {
		t.Fatalf("column %q missing from header %q", col, header)
	}
	if !strings.HasPrefix(row[colIdx:], value) {
		t.Fatalf("%s misaligned at %d: header=%q row=%q want prefix %q", col, colIdx, header, row, value)
	}
}

func quoteHeaderLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "CID") && strings.Contains(line, "SIZE") {
			return line
		}
	}
	return ""
}

func quoteRowContaining(out, substr string) string {
	prefix := tableCID(substr)
	for _, line := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, prefix) && !strings.HasPrefix(trim, "CID") {
			return line
		}
	}
	return ""
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
