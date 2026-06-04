package main

import (
	"fmt"
	"os"

	"github.com/skroczek/sshsign"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign <private-key> <file>",
	Short: "Sign a file",
	Args:  cobra.ExactArgs(2),
	RunE:  runSign,
}

var signMode string
var signNamespace string
var signOutput string

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVarP(&signMode, "mode", "m", "sshsig", "Signing mode: simple or sshsig")
	signCmd.Flags().StringVarP(&signNamespace, "namespace", "n", "file", "SSHSIG namespace (sshsig mode only)")
	signCmd.Flags().StringVarP(&signOutput, "output", "o", "", "Output file (default: <file>.sig)")
}

func runSign(cmd *cobra.Command, args []string) error {
	privateKey, file := args[0], args[1]

	outFile := signOutput
	if outFile == "" {
		outFile = file + ".sig"
	}

	switch signMode {
	case "simple":
		sig, err := sshsign.SignFile(privateKey, file)
		if err != nil {
			return err
		}
		if err := os.WriteFile(outFile, []byte(sig+"\n"), 0644); err != nil {
			return fmt.Errorf("write signature: %w", err)
		}

	case "sshsig":
		sig, err := sshsign.SshsigSignFile(privateKey, file, signNamespace)
		if err != nil {
			return err
		}
		if err := os.WriteFile(outFile, []byte(sig), 0644); err != nil {
			return fmt.Errorf("write signature: %w", err)
		}

	default:
		return fmt.Errorf("unknown mode %q, use 'simple' or 'sshsig'", signMode)
	}

	fmt.Printf("Signature saved: %s\n", outFile)
	return nil
}
