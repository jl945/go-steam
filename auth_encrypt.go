package steam

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// EncryptPassword encrypts the password using RSA public key
func EncryptPassword(password string, modHex string, expHex string) (string, error) {
	// Convert hex strings to big.Int
	modBytes, err := hex.DecodeString(modHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode modulus: %w", err)
	}

	expBytes, err := hex.DecodeString(expHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode exponent: %w", err)
	}

	mod := new(big.Int).SetBytes(modBytes)
	exp := new(big.Int).SetBytes(expBytes)

	// Create RSA public key
	pubKey := &rsa.PublicKey{
		N: mod,
		E: int(exp.Int64()),
	}

	// Encrypt the password
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(password))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt password: %w", err)
	}

	// Encode to base64
	return base64.StdEncoding.EncodeToString(encrypted), nil
}
