// Command mkcert is a simple zero-config tool to make locally trusted development certificates.
// It automatically creates and installs a local CA in the system root store, and generates
// locally-trusted certificates.
package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const usage = `Usage of mkcert:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate a single certificate for multiple hostnames.

	$ mkcert '*.example.com'
	Generate a wildcard certificate.

	$ mkcert -uninstall
	Uninstall the local CA from the system trust store.

For more options, run "mkcert -help".
`

func main() {
	log.SetFlags(0)

	var (
		installFlag   = flag.Bool("install", false, "Install the local CA in the system trust store")
		uninstallFlag = flag.Bool("uninstall", false, "Uninstall the local CA from the system trust store")
		pkcs12Flag    = flag.Bool("pkcs12", false, "Generate a PKCS#12 file instead of PEM")
		// Default to ecdsa=true since ECDSA certs are smaller and faster than RSA.
		// Note: set to false if you need RSA for compatibility with older clients.
		ecdsaFlag     = flag.Bool("ecdsa", true, "Generate a certificate with an ECDSA key")
		clientFlag    = flag.Bool("client", false, "Generate a certificate for client authentication")
		helpFlag      = flag.Bool("help", false, "Show this help message")
		certFileFlag  = flag.String("cert-file", "", "Custom output path for the certificate PEM file")
		keyFileFlag   = flag.String("key-file", "", "Custom output path for the key PEM file")
		p12FileFlag   = flag.String("p12-file", "", "Custom output path for the PKCS#12 file")
		csrFlag       = flag.String("csr", "", "Use an existing CSR to issue a certificate")
		carootFlag    = flag.Bool("CAROOT", false, "Print the CA certificate and key storage location")
	)

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if *helpFlag {
		flag.Usage()
		return
	}

	m := &mkcert{
		pkcs12:   *pkcs12Flag,
		ecdsa:    *ecdsaFlag,
		client:   *clientFlag,
		certFile: *certFileFlag,
		keyFile:  *keyFileFlag,
		p12File:  *p12FileFlag,
		csrPath:  *csrFlag,
	}

	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: cannot use -CAROOT with -install or -uninstall")
		}
		fmt.Println(getCAROOT())
		return
	}

	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: cannot use -install and -uninstall together")
	}

	if *installFlag {
		m.install()
		if flag.NArg() == 0 {
			return
		}
	}
	if *uninstallFlag {
		m.uninstall()
		return
	}

	if flag.NArg() == 0 && *csrFlag == "" {
		flag.Usage()
		return
	}

	hosts := flag.Args()
	if err := validateHosts(hosts); err != nil {
		log.Fatalf("ERROR: %s", err)
	}

	m.makeCert(hosts)
}

// validateHosts checks that the provided hostnames/IPs/URIs are valid.
// Wildcards (e.g. *.example.com) are allowed only as the leftmost label.
// Each host must be a va