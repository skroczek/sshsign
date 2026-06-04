package sshsign

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// appendString encodes a string in RFC4253 wire format (uint32 length + bytes).
func appendString(b []byte, s string) []byte {
	b = appendUint32(b, uint32(len(s)))
	return append(b, []byte(s)...)
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// readString reads an RFC4253-encoded string (uint32 length prefix).
func readString(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("too short for string length")
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint32(len(b)-4) < n {
		return nil, nil, fmt.Errorf("string too short: need %d, have %d", n, len(b)-4)
	}
	return b[4 : 4+n], b[4+n:], nil
}

// unarmor strips the PEM-like header/footer and decodes base64.
func unarmor(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	s = strings.ReplaceAll(s, "-----BEGIN SSH SIGNATURE-----", "")
	s = strings.ReplaceAll(s, "-----END SSH SIGNATURE-----", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.TrimSpace(s)
	return base64.StdEncoding.DecodeString(s)
}

// buildSignedData constructs the to-be-signed blob per PROTOCOL.sshsig §3.
func buildSignedData(namespace, hashAlgo string, msgHash []byte) []byte {
	var b []byte
	b = append(b, []byte("SSHSIG")...)
	b = appendString(b, namespace)
	b = appendString(b, "") // reserved
	b = appendString(b, hashAlgo)
	b = appendString(b, string(msgHash))
	return b
}
