package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "github.com/skroczek/sshsign",
	Short: "Sign and verify files using SSH keys",
	Long: `github.com/skroczek/sshsign signs and verifies files using SSH private/public keys.

Two modes are supported:
  simple  – compact base64 signature (not compatible with ssh-keygen)
  sshsig  – SSHSIG format compatible with ssh-keygen -Y sign/verify (default)`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
