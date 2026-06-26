package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Password hashing parameters. PBKDF2-HMAC-SHA256 is a standard, salted,
// iterated key-derivation function (RFC 8018). The iteration count follows
// OWASP guidance for PBKDF2-HMAC-SHA256.
const (
	pbkdf2Iterations = 210_000
	saltLen          = 16
	keyLen           = 32
	hashScheme       = "pbkdf2-sha256"
)

// HashPassword returns a self-describing, storable hash of the form:
//
//	pbkdf2-sha256$<iterations>$<base64-salt>$<base64-derived-key>
//
// A fresh random salt is generated per call, so identical passwords produce
// different stored values.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, keyLen)
	return fmt.Sprintf("%s$%d$%s$%s",
		hashScheme,
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

// VerifyPassword reports whether password matches the stored encoded hash.
// Comparison is constant-time to avoid timing side channels.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// pbkdf2SHA256 implements PBKDF2 (RFC 8018) using HMAC-SHA256 as the PRF.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen

	dk := make([]byte, 0, numBlocks*hLen)
	idx := make([]byte, 4)

	for block := 1; block <= numBlocks; block++ {
		idx[0] = byte(block >> 24)
		idx[1] = byte(block >> 16)
		idx[2] = byte(block >> 8)
		idx[3] = byte(block)

		prf.Reset()
		prf.Write(salt)
		prf.Write(idx)
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}
