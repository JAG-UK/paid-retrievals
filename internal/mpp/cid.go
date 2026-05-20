package mpp

import (
	"fmt"
	"strings"

	cid "github.com/ipfs/go-cid"
)

func validateIPFSCID(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return ErrInvalidHeader
	}
	if _, err := cid.Decode(s); err != nil {
		return fmt.Errorf("%w: invalid ipfs cid", ErrInvalidHeader)
	}
	return nil
}
