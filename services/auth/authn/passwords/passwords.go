//services/auth/authn/passwords/passwords.go
package passwords

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams holds the parameters for Argon2id hashing.
// These parameters can be tuned based on your security requirements and server resources.
type Argon2idParams struct {
	Memory      uint32 // Memory cost in KiB
	Iterations  uint32 // Time cost (number of passes)
	Parallelism uint8  // Parallelism factor (threads)
	SaltLength  uint32 // Length of the salt in bytes
	KeyLength   uint32 // Length of the derived key (hash) in bytes
}

// DefaultArgon2idParams provides recommended default parameters.
// OWASP recommendations suggest t>=2, m>=19MiB (19456 KiB).
// Adjust these based on performance testing on your hardware.
var DefaultArgon2idParams = &Argon2idParams{
	Memory:      64 * 1024, // 64MB
	Iterations:  3,
	Parallelism: 4, // Adjust based on available CPU cores
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword securely hashes a password using Argon2id and returns a PHC string.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}
	params := DefaultArgon2idParams // Use default parameters

	// 1. Generate a cryptographically secure random salt.
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// 2. Compute the Argon2id hash.
	// argon2.IDKey(password, salt, time, memory, threads, keyLen)
	// Note: `params.Memory` is already in KiB as required by the spec if you define it that way.
	// The argon2.IDKey function itself handles memory in KiB.
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	// 3. Encode salt and hash to Base64 (raw encoding, no padding for PHC).
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// 4. Format as PHC string: $argon2id$v=<version>$m=<memory_kib>,t=<iterations>,p=<parallelism>$<salt>$<hash>
	// Example: $argon2id$v=19$m=65536,t=3,p=4$YWFhYWFhYWFhYWFhYWFhYQ$ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZg
	phcString := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,    // Argon2 version (0x13, which is 19 decimal)
		params.Memory,     // Memory cost in KiB
		params.Iterations, // Iterations (time cost)
		params.Parallelism,// Parallelism factor
		b64Salt,           // Base64 encoded salt
		b64Hash,           // Base64 encoded hash
	)
	return phcString, nil
}

// VerifyPassword compares a plaintext password with a stored Argon2id hash (PHC format).
func VerifyPassword(password string, encodedHash string) (bool, error) {	// To be used in the authentication/login service.
	if password == "" || encodedHash == "" {
		return false, errors.New("password and encoded hash must not be empty")
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid argon2id hash format: expected 6 parts, got %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported hash algorithm: expected 'argon2id', got '%s'", parts[1])
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, fmt.Errorf("failed to parse argon2id version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("mismatched argon2 version: expected %d, got %d", argon2.Version, version)
	}

	params := Argon2idParams{} // Create a new params struct to fill
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return false, fmt.Errorf("failed to parse argon2id parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt from hash: %w", err)
	}

	// Decode the stored hash first, then set KeyLength based on its length.
	decodedStoredHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode stored hash: %w", err)
	}
    // Set KeyLength based on the actual length of the decoded hash.
    params.KeyLength = uint32(len(decodedStoredHash))


	// Compute the hash of the provided password using the extracted salt and parameters.
	comparisonHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	// Compare the computed hash with the stored hash in constant time to prevent timing attacks.
	if subtle.ConstantTimeCompare(decodedStoredHash, comparisonHash) == 1 {
		return true, nil // Passwords match
	}
	return false, nil // Passwords do not match
}
