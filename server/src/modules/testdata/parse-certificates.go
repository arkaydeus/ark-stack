// Independent strict parser and chain verification for the TypeScript PKI tests.
// Run with: go run parse-certificates.go ca.pem leaf.pem
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

func certificate(path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		panic("missing certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}

func main() {
	ca, leaf := certificate(os.Args[1]), certificate(os.Args[2])
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: leaf.NotBefore.Add(time.Hour),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("CA and leaf parsed; client chain verified")
}
