# sshsign

Sign and verify files using SSH keys — usable as a Go library or as a CLI binary.

Two modes are supported:

- **sshsig** – armored format, fully compatible with `ssh-keygen -Y sign/verify` (default)
- **simple** – compact base64 signature, not compatible with ssh-keygen

## CLI

### Install

```bash
go install github.com/skroczek/sshsign/cmd/sshsign@latest
```

### Sign

```bash
# sshsig mode (default, ssh-keygen compatible)
sshsign sign ~/.ssh/id_ed25519 myfile.txt
# → writes myfile.txt.sig

# simple mode
sshsign sign --mode simple ~/.ssh/id_ed25519 myfile.txt

# custom namespace (sshsig only, default: "file")
sshsign sign --namespace git ~/.ssh/id_ed25519 myfile.txt

# custom output path
sshsign sign --output myfile.txt.sig ~/.ssh/id_ed25519 myfile.txt
```

### Verify

```bash
# sshsig mode (default)
sshsign verify ~/.ssh/id_ed25519.pub myfile.txt myfile.txt.sig

# simple mode
sshsign verify --mode simple ~/.ssh/id_ed25519.pub myfile.txt myfile.txt.sig
```

The CLI uses the SSH agent automatically if `SSH_AUTH_SOCK` is set and the matching key is loaded. It falls back to reading the private key from disk (prompting for passphrase if needed).

### Cross-verify with ssh-keygen

Signatures created in sshsig mode can be verified with stock `ssh-keygen`:

```bash
ssh-keygen -Y verify -f allowed_signers -I user@example.com -n file -s myfile.txt.sig < myfile.txt
```

where `allowed_signers` contains a line like:

```
user@example.com ssh-ed25519 AAAA...
```

## Library

```bash
go get github.com/skroczek/sshsign
```

Each operation comes in two variants:

| File paths | Bytes / Signer |
|---|---|
| `SignFile(keyPath, filePath)` | `SignBytes(signer, data)` |
| `VerifyFile(keyPath, filePath, sig)` | `VerifyBytes(pubKey, data, sig)` |
| `SshsigSignFile(keyPath, filePath, ns)` | `SshsigSignBytes(signer, data, ns)` |
| `SshsigVerifyFile(keyPath, filePath, sigPath, ns)` | `SshsigVerifyBytes(pubKey, data, armored, ns)` |

The `*File` variants load keys and files from disk and call the `*Bytes` variant internally.

### Examples

```go
import "github.com/skroczek/sshsign"

// Sign a file (sshsig, ssh-keygen compatible)
armored, err := sshsign.SshsigSignFile("~/.ssh/id_ed25519", "myfile.txt", "file")

// Verify it
err = sshsign.SshsigVerifyFile("~/.ssh/id_ed25519.pub", "myfile.txt", "myfile.txt.sig", "file")

// Or work with raw bytes and a pre-loaded signer
armored, err := sshsign.SshsigSignBytes(signer, data, "file")
err = sshsign.SshsigVerifyBytes(pubKey, data, armored, "file")

// Simple mode (compact base64)
sig, err := sshsign.SignFile("~/.ssh/id_ed25519", "myfile.txt")
err = sshsign.VerifyFile("~/.ssh/id_ed25519.pub", "myfile.txt", sig)
```

Key loading is handled by `LoadSigner(path string)` — tries the SSH agent first, falls back to the key file on disk.

## Project structure

```
sshsign/
├── key.go          # LoadSigner, SignerFromAgent, SignerFromFile
├── simple.go       # SignBytes, SignFile, VerifyBytes, VerifyFile
├── sshsig.go       # SshsigSignBytes, SshsigSignFile, SshsigVerifyBytes, SshsigVerifyFile
├── helpers.go      # internal wire-format helpers
└── cmd/sshsign/    # CLI binary (cobra)
    ├── main.go
    ├── root.go
    ├── sign.go
    └── verify.go
```
