package steam

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"math/rand"
	"time"
)

// createMachineID creates a machine ID in the binary KV format used by Steam
// 参考 node-steam-user 09-logon.js:876-906
// Machine IDs are binary KV objects with root key MessageObject and three hashes named BB3, FF2, and 3B3.
func createMachineID(valBB3, valFF2, val3B3 string) []byte {
	buffer := new(bytes.Buffer)

	// Root key: MessageObject
	buffer.WriteByte(0)                    // Type 0: end of object (but actually start marker)
	buffer.WriteString("MessageObject\x00") // C string (null-terminated)

	// BB3 hash
	buffer.WriteByte(1)          // Type 1: string
	buffer.WriteString("BB3\x00") // C string
	buffer.WriteString(sha1Hash(valBB3) + "\x00")

	// FF2 hash
	buffer.WriteByte(1)          // Type 1: string
	buffer.WriteString("FF2\x00") // C string
	buffer.WriteString(sha1Hash(valFF2) + "\x00")

	// 3B3 hash
	buffer.WriteByte(1)          // Type 1: string
	buffer.WriteString("3B3\x00") // C string
	buffer.WriteString(sha1Hash(val3B3) + "\x00")

	// End markers
	buffer.WriteByte(8) // End of object
	buffer.WriteByte(8) // End of object

	return buffer.Bytes()
}

// sha1Hash returns the SHA1 hash of the input string as hex
func sha1Hash(input string) string {
	h := sha1.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// generateRandomMachineID generates a random machine ID
// 参考 node-steam-user 09-logon.js:593-595
func generateRandomMachineID() []byte {
	rand.Seed(time.Now().UnixNano())
	return createMachineID(
		fmt.Sprintf("%f", rand.Float64()),
		fmt.Sprintf("%f", rand.Float64()),
		fmt.Sprintf("%f", rand.Float64()),
	)
}

// generateMachineIDFromSteamID generates a machine ID based on a Steam ID
// 参考 node-steam-user 09-logon.js:582-587
func generateMachineIDFromSteamID(steamID uint64) []byte {
	identifier := fmt.Sprintf("%d", steamID)
	return createMachineID(
		identifier,
		identifier,
		identifier,
	)
}
