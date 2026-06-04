package sshsign

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// sshsigParsed holds the fields extracted from an SSHSIG blob.
type sshsigParsed struct {
	version   uint32
	publicKey ssh.PublicKey
	namespace string
	reserved  string
	hashAlgo  string
	signature *ssh.Signature
}

// SshsigSignBytes creates an ssh-keygen-compatible SSHSIG signature over data.
// namespace is typically "file" (matching ssh-keygen -Y sign -n file).
func SshsigSignBytes(signer ssh.Signer, data []byte, namespace string) (string, error) {
	hash := sha512.Sum512(data)
	signedData := buildSignedData(namespace, "sha512", hash[:])

	sig, err := signer.Sign(rand.Reader, signedData)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	var blob []byte
	blob = append(blob, []byte("SSHSIG")...)
	blob = appendUint32(blob, 1) // SIG_VERSION
	blob = appendString(blob, string(signer.PublicKey().Marshal()))
	blob = appendString(blob, namespace)
	blob = appendString(blob, "") // reserved
	blob = appendString(blob, "sha512")
	blob = appendString(blob, string(ssh.Marshal(sig)))

	b64 := base64.StdEncoding.EncodeToString(blob)
	armored := "-----BEGIN SSH SIGNATURE-----\n"
	for len(b64) > 76 {
		armored += b64[:76] + "\n"
		b64 = b64[76:]
	}
	armored += b64 + "\n-----END SSH SIGNATURE-----\n"

	return armored, nil
}

// SshsigSignFile loads the private key and file from disk, then calls SshsigSignBytes.
func SshsigSignFile(privateKeyPath, filePath, namespace string) (string, error) {
	signer, err := LoadSigner(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	return SshsigSignBytes(signer, data, namespace)
}

// SshsigVerifyBytes verifies an armored SSHSIG signature against data.
// pubKey may be nil to skip key identity check.
func SshsigVerifyBytes(pubKey ssh.PublicKey, data []byte, sigArmored, namespace string) error {
	hash := sha512.Sum512(data)

	sigBlob, err := unarmor([]byte(sigArmored))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	parsed, err := parseSshsigBlob(sigBlob)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	if pubKey != nil {
		if string(pubKey.Marshal()) != string(parsed.publicKey.Marshal()) {
			return fmt.Errorf("public key mismatch: signed with %s",
				ssh.FingerprintSHA256(parsed.publicKey))
		}
	}

	signedData := buildSignedData(namespace, "sha512", hash[:])
	if err := parsed.publicKey.Verify(signedData, parsed.signature); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	return nil
}

// SshsigVerifyFile loads the public key, file, and signature file from disk,
// then calls SshsigVerifyBytes. publicKeyPath may be empty to skip key identity check.
func SshsigVerifyFile(publicKeyPath, filePath, sigPath, namespace string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	sigArmored, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read signature file: %w", err)
	}

	var pubKey ssh.PublicKey
	if publicKeyPath != "" {
		pubBytes, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return fmt.Errorf("read public key: %w", err)
		}
		pubKey, _, _, _, err = ssh.ParseAuthorizedKey(pubBytes)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}
	}

	return SshsigVerifyBytes(pubKey, data, string(sigArmored), namespace)
}

func parseSshsigBlob(blob []byte) (*sshsigParsed, error) {
	if len(blob) < 6 || string(blob[:6]) != "SSHSIG" {
		return nil, errors.New("not a valid sshsig blob (missing magic)")
	}
	rest := blob[6:]

	if len(rest) < 4 {
		return nil, errors.New("blob too short (version)")
	}
	version := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if version != 1 {
		return nil, fmt.Errorf("unknown sshsig version: %d", version)
	}

	pubKeyBytes, rest, err := readString(rest)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	ns, rest, err := readString(rest)
	if err != nil {
		return nil, fmt.Errorf("read namespace: %w", err)
	}

	reserved, rest, err := readString(rest)
	if err != nil {
		return nil, fmt.Errorf("read reserved: %w", err)
	}

	hashAlgo, rest, err := readString(rest)
	if err != nil {
		return nil, fmt.Errorf("read hash_algorithm: %w", err)
	}

	sigBytes, _, err := readString(rest)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		return nil, fmt.Errorf("unmarshal signature: %w", err)
	}

	return &sshsigParsed{
		version:   version,
		publicKey: pubKey,
		namespace: string(ns),
		reserved:  string(reserved),
		hashAlgo:  string(hashAlgo),
		signature: &sig,
	}, nil
}
