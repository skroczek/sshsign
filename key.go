package sshsign

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// LoadSigner tries the SSH agent first, then falls back to loading from file.
func LoadSigner(path string) (ssh.Signer, error) {
	if signer, err := SignerFromAgent(path); err == nil {
		return signer, nil
	}
	return SignerFromFile(path)
}

// SignerFromAgent connects to the SSH agent and returns a signer for the key
// matching the public key at <keyPath>.pub. If the .pub file is absent, the
// first key in the agent is used.
func SignerFromAgent(keyPath string) (ssh.Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, errors.New("SSH_AUTH_SOCK not set")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect to agent: %w", err)
	}
	// conn intentionally left open – the signer needs it

	ag := agent.NewClient(conn)

	pubKeyPath := keyPath + ".pub"
	pubBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		// No .pub file: fall back to first agent key
		signers, err := ag.Signers()
		if err != nil || len(signers) == 0 {
			return nil, fmt.Errorf("no keys in agent: %w", err)
		}
		return signers[0], nil
	}

	wantPub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	signers, err := ag.Signers()
	if err != nil {
		return nil, fmt.Errorf("agent signers: %w", err)
	}

	for _, s := range signers {
		if s.PublicKey().Type() == wantPub.Type() &&
			string(s.PublicKey().Marshal()) == string(wantPub.Marshal()) {
			return s, nil
		}
	}

	return nil, errors.New("key not found in agent")
}

// SignerFromFile loads a private key from disk, prompting for passphrase if needed.
func SignerFromFile(path string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err == nil {
		return signer, nil
	}

	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); !ok {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	fmt.Print("Passphrase: ")
	var passphrase string
	fmt.Scanln(&passphrase)

	signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("wrong passphrase: %w", err)
	}
	return signer, nil
}
