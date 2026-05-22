package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func initCLIUsage(cmd *cobra.Command) {
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n\n", err)
		if uerr := c.Usage(); uerr != nil {
			return uerr
		}
		return err
	})
	for _, sub := range cmd.Commands() {
		initCLIUsage(sub)
	}
}
