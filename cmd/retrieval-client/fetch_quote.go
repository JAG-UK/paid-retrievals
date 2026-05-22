package main

import (
	"fmt"
	"io"
	"strings"
)

// tableCID shortens a CID for fixed-width quote columns (ASCII ellipsis, single-column width).
func tableCID(cid string) string {
	if len(cid) <= 16 {
		return cid
	}
	return cid[:10] + "..." + cid[len(cid)-6:]
}

func formatQuoteSize(totalBytes int64) string {
	if totalBytes < 0 {
		return "—"
	}
	return formatBytes(totalBytes)
}

func quoteColumnWidths(items []challengeItem) (cidW, typeW, sizeW, priceW int) {
	cidW = len("CID")
	typeW = len("TYPE")
	sizeW = len("SIZE")
	priceW = len("PRICE")
	for _, it := range items {
		if w := len(tableCID(it.CID)); w > cidW {
			cidW = w
		}
		typ := "paid"
		price := it.PriceUSDFC + " USDFC"
		size := formatQuoteSize(it.TotalBytes)
		if it.Free {
			typ = "free"
			price = "—"
		}
		if w := len(typ); w > typeW {
			typeW = w
		}
		if w := len(size); w > sizeW {
			sizeW = w
		}
		if w := len(price); w > priceW {
			priceW = w
		}
	}
	return cidW, typeW, sizeW, priceW
}

func printFetchQuote(out io.Writer, items []challengeItem, totalUSDFC string) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Quote:")
	cidW, typeW, sizeW, priceW := quoteColumnWidths(items)
	rowFmt := fmt.Sprintf("  %%-%ds  %%-%ds  %%-%ds  %%-%ds  %%s\n", cidW, typeW, sizeW, priceW)
	fmt.Fprintf(out, rowFmt, "CID", "TYPE", "SIZE", "PRICE", "SOURCE")
	for _, it := range items {
		typ := "paid"
		price := it.PriceUSDFC + " USDFC"
		size := formatQuoteSize(it.TotalBytes)
		source := "—"
		if it.Base != nil {
			source = it.Base.String()
		}
		if it.Free {
			typ = "free"
			price = "—"
			if it.Base != nil {
				source = it.Base.String()
			}
		}
		fmt.Fprintf(out, rowFmt, tableCID(it.CID), typ, size, price, source)
	}

	var paid, free int
	for _, it := range items {
		if it.Free {
			free++
		} else {
			paid++
		}
	}
	fmt.Fprintln(out)
	if paid > 0 {
		fmt.Fprintf(out, "Total: %s USDFC for %d paid piece(s)", totalUSDFC, paid)
		if free > 0 {
			fmt.Fprintf(out, "; %d free", free)
		}
		fmt.Fprintln(out, ".")
		fmt.Fprintln(out, "Chain: this may take some time - several transactions to prepare then one charge per payee, each ~30s.")
	} else {
		fmt.Fprintf(out, "All %d piece(s) are free; no Filecoin Pay charge required.\n", free)
	}
	fmt.Fprintln(out, "Download: large CAR files may take a long time; progress is shown when running on a terminal.")
}

func countPaidPayees(items []challengeItem) int {
	seen := map[string]struct{}{}
	for _, it := range items {
		if it.Free {
			continue
		}
		p := strings.TrimSpace(it.Payee0x)
		if p == "" {
			continue
		}
		seen[p] = struct{}{}
	}
	return len(seen)
}
