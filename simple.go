package sshsign

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SignBytes signs data with the given signer and returns a base64-encoded signature.
func SignBytes(signer ssh.Signer, data []byte) (string, error) {
	hash := sha512.Sum512(data)
	sig, err := signer.Sign(rand.Reader, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ssh.Marshal(sig)), nil
}

// SignFile loads the private key and file from disk, then calls SignBytes.
func SignFile(privateKeyPath, filePath string) (string, error) {
	signer, err := LoadSigner(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	return SignBytes(signer, data)
}

// VerifyBytes verifies a base64-encoded signature against data using the given public key.
func VerifyBytes(pubKey ssh.PublicKey, data []byte, sigBase64 string) error {
	hash := sha512.Sum512(data)

	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigBase64))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		return fmt.Errorf("unmarshal signature: %w", err)
	}
	if err := pubKey.Verify(hash[:], &sig); err != nil {
		return errors.New("invalid signature")
	}
	return nil
}

// VerifyFile loads the public key and file from disk, reads the signature string,
// then calls VerifyBytes.
func VerifyFile(publicKeyPath, filePath, sigBase64 string) error {
	keyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	return VerifyBytes(pubKey, data, sigBase64)
}
