//go:build darwin

package nexodus

import "fmt"

// CheckExistingKeys will look for an existing key pair, if a pair is not found this method
// will return an error message.
func CheckExistingKeys() (string, string, error) {
	publicKey, err := readKeyFile(DarwinPublicKeyFile)
	if err != nil {
		return "", "", err
	}
	privateKey, err := readKeyFile(DarwinPrivateKeyFile)
	if err != nil {
		return "", "", err
	}
	if publicKey != "" && privateKey != "" {
		return publicKey, privateKey, nil
	}
	return "", "", fmt.Errorf("existing key files are broken (empty, non-readable)")
}

// GenerateNewKeys will generate a new pair and write them to location on the disk depending on the OS
func GenerateNewKeys() (string, string, error) {
	publicKey, privateKey, err := generateKeyPair(DarwinPublicKeyFile, DarwinPrivateKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("Unable to generate a key/pair: %w", err)
	}
	return publicKey, privateKey, nil
}
