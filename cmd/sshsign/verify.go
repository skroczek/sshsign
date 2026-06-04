package main

import (
	"fmt"
	"os"

	"github.com/skroczek/sshsign"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <public-key> <file> <sig-file>",
	Short: "Verify a file signature",
	Args:  cobra.ExactArgs(3),
	RunE:  runVerify,
}

var verifyMode string
var verifyNamespace string

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringVarP(&verifyMode, "mode", "m", "sshsig", "Verification mode: simple or sshsig")
	verifyCmd.Flags().StringVarP(&verifyNamespace, "namespace", "n", "file", "SSHSIG namespace (sshsig mode only)")
}

func runVerify(cmd *cobra.Command, args []string) error {
	publicKey, file, sigFile := args[0], args[1], args[2]

	switch verifyMode {
	case "simple":
		sigBytes, err := os.ReadFile(sigFile)
		if err != nil {
			return fmt.Errorf("read signature file: %w", err)
		}
		if err := sshsign.VerifyFile(publicKey, file, string(sigBytes)); err != nil {
			fmt.Fprintln(os.Stderr, "✗", err)
			os.Exit(1)
		}

	case "sshsig":
		if err := sshsign.SshsigVerifyFile(publicKey, file, sigFile, verifyNamespace); err != nil {
			fmt.Fprintln(os.Stderr, "✗", err)
			os.Exit(1)
		}

	default:
		return fmt.Errorf("unknown mode %q, use 'simple' or 'sshsig'", verifyMode)
	}

	fmt.Println("✓ valid signature")
	return nil
}
