package nexodus

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// default key pair file locations (windows needs work)
const (
	LinuxPublicKeyFile    = "/etc/wireguard/public.key"
	LinuxPrivateKeyFile   = "/etc/wireguard/private.key"
	DarwinPublicKeyFile   = "/usr/local/etc/wireguard/public.key"
	DarwinPrivateKeyFile  = "/usr/local/etc/wireguard/private.key"
	WindowsPublicKeyFile  = "C:/wireguard/public.key"
	WindowsPrivateKeyFile = "C:/wireguard/private.key"
	publicKeyPermissions  = 0644
	privateKeyPermissions = 0600
)

// generateKeyPair a key pair and write them to disk
func generateKeyPair(publicKeyFile, privateKeyFile string) (string, string, error) {
	cmd := exec.Command(wgBinary, "genkey")
	privateKey, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey error: %w", err)
	}

	cmd = exec.Command(wgBinary, "pubkey")
	cmd.Stdin = bytes.NewReader(privateKey)
	publicKey, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg pubkey error: %w", err)
	}
	wgPubKey := strings.TrimSpace(string(publicKey))
	wgPvtKey := strings.TrimSpace(string(privateKey))

	// write the new keys to disk
	err = WriteToFile(wgPubKey, publicKeyFile, publicKeyPermissions)
	if err != nil {
		return "", "", err
	}
	err = WriteToFile(wgPvtKey, privateKeyFile, privateKeyPermissions)
	if err != nil {
		return "", "", err
	}

	return wgPubKey, wgPvtKey, nil
}

// readKeyFile reads the contents of a key file
func readKeyFile(keyFile string) (string, error) {
	if !FileExists(keyFile) {
		return "", fmt.Errorf("key file does not exist: %s", keyFile)
	}
	key, err := readKeyFileToString(keyFile)
	if err != nil {
		return "", err
	}
	return key, nil
}

// readKeyFileToString reads the key file and strips any newline chars that create wireguard issues
func readKeyFileToString(s string) (string, error) {
	buf, err := os.ReadFile(s)
	if err != nil {
		return "", fmt.Errorf("unable to read file: %w", err)
	}
	rawStr := string(buf)
	return strings.Replace(rawStr, "\n", "", -1), nil
}
