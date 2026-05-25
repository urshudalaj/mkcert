// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// trustStore manages the system trust store for local CA certificates.
type trustStore struct {
	caRoot *x509.Certificate
	caRootPEM []byte
}

// installCA installs the local CA certificate into the system trust store.
func (m *mkcert) installCA() {
	switch runtime.GOOS {
	case "darwin":
		m.installDarwin()
	case "linux":
		m.installLinux()
	case "windows":
		m.installWindows()
	default:
		log.Printf("WARNING: platform %s is not supported for automatic CA installation\n", runtime.GOOS)
	}
}

// uninstallCA removes the local CA certificate from the system trust store.
func (m *mkcert) uninstallCA() {
	switch runtime.GOOS {
	case "darwin":
		m.uninstallDarwin()
	case "linux":
		m.uninstallLinux()
	case "windows":
		m.uninstallWindows()
	default:
		log.Printf("WARNING: platform %s is not supported for automatic CA removal\n", runtime.GOOS)
	}
}

// installDarwin installs the CA into the macOS system keychain.
func (m *mkcert) installDarwin() {
	cmd := exec.Command(
		"security", "add-trusted-cert",
		"-d",
		"-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		m.caRootFile(),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("ERROR: failed to install CA on macOS: %s\n%s", err, out)
	}
	log.Printf("The local CA is now installed in the system trust store (requires password)!\n")
}

// uninstallDarwin removes the CA from the macOS system keychain.
func (m *mkcert) uninstallDarwin() {
	cmd := exec.Command(
		"security", "remove-trusted-cert",
		"-d",
		m.caRootFile(),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("ERROR: failed to remove CA on macOS: %s\n%s", err, out)
	}
	log.Printf("The local CA has been removed from the system trust store!\n")
}

// installLinux installs the CA into the Linux system trust store.
func (m *mkcert) installLinux() {
	// Try common Linux trust store locations
	locations := []struct {
		dir    string
		cmd    []string
	}{
		{"/usr/local/share/ca-certificates/", []string{"update-ca-certificates"}},
		{"/etc/pki/ca-trust/source/anchors/", []string{"update-ca-trust", "extract"}},
		{"/etc/ca-certificates/trust-source/anchors/", []string{"trust", "extract-compat"}},
	}

	for _, loc := range locations {
		if _, err := os.Stat(loc.dir); err == nil {
			dest := filepath.Join(loc.dir, "mkcert-ca.crt")
			if err := copyFile(m.caRootFile(), dest); err != nil {
				log.Fatalf("ERROR: failed to copy CA to %s: %v", dest, err)
			}
			out, err := exec.Command(loc.cmd[0], loc.cmd[1:]...).CombinedOutput()
			if err != nil {
				log.Fatalf("ERROR: failed to update CA trust: %s\n%s", err, out)
			}
			log.Printf("The local CA is now installed in the system trust store!\n")
			return
		}
	}
	log.Printf("WARNING: no supported Linux trust store found. Manual installation may be required.\n")
}

// uninstallLinux removes the CA from the Linux system trust store.
func (m *mkcert) uninstallLinux() {
	locations := []string{
		"/usr/local/share/ca-certificates/mkcert-ca.crt",
		"/etc/pki/ca-trust/source/anchors/mkcert-ca.crt",
		"/etc/ca-certificates/trust-source/anchors/mkcert-ca.crt",
	}
	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			if err := os.Remove(loc); err != nil {
				log.Fatalf("ERROR: failed to remove CA from %s: %v", loc, err)
			}
			log.Printf("The local CA has been removed from the system trust store!\n")
			return
		}
	}
}

// installWindows installs the CA into the Windows certificate store.
func (m *mkcert) installWindows() {
	cmd := exec.Command("certutil", "-addstore", "-f", "ROOT", m.caRootFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("ERROR: failed to install CA on Windows: %s\n%s", err, out)
	}
	log.Printf("The local CA is now installed in the Windows trust store!\n")
}

// uninstallWindows removes the CA from the Windows certificate store.
func (m *mkcert) uninstallWindows() {
	cmd := exec.Command("certutil", "-delstore", "ROOT", fmt.Sprintf("%x", m.caRoot.SerialNumber))
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("ERROR: failed to remove CA on Windows: %s\n%s", err, out)
	}
	log.Printf("The local CA has been removed from the Windows trust store!\n")
}
