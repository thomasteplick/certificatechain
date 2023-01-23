// package rsachain creates an RSA certificate chain consisting of
// a root CA, zero or more intermediate CAs, and the end-entity certificate.

package rsachain

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/thomasteplick/certchain"
)

const (
	certsDir       = "../../certs"
	keysDir        = "../../private"
	crlDir         = "../../crl"
	openssl        = "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"
	trustChainPath = "trustChainRSA.pem" // cat of CAs and End-entity certs
)

// RSA chain data
type RSAChain struct {
	KeySizeRoot         int
	KeySizeInter1       int
	KeySizeInter2       int
	KeySizeEndEntity    int
	Root                *x509.Certificate
	Inter1              *x509.Certificate
	Inter2              *x509.Certificate
	EndEntity           *x509.Certificate
	rootRSAkey          *rsa.PrivateKey
	intermediate1RSAkey *rsa.PrivateKey
	intermediate2RSAkey *rsa.PrivateKey
	endentityRSAkey     *rsa.PrivateKey
}

// trust chain file
var trustChainFile *os.File

// DisplayCertificate prints out the certificate
func (chain *RSAChain) DisplayCertificate(pemfile string, w http.ResponseWriter) {
	var h3 string

	// temporary x509 certificate file
	const tmp = "temp.text"

	switch pemfile {
	case "endEntity.pem":
		h3 = "End-entity Certificate"
	case "inter1CA.pem":
		h3 = "Intermediate1 Certificate Authority"
	case "inter2CA.pem":
		h3 = "Intermediate2 Certificate Authority"
	case "rootCA.pem":
		h3 = "Root Certificate Authority"
	default:
		fmt.Printf("Unsupported level in DisplayCertificate: %s\n", pemfile)
		return
	}
	_, err := fmt.Fprintf(w, `<h3>%s</h3>`, h3)
	if err != nil {
		fmt.Printf("DisplayCertificate h3 error: %v\n", err)
	}

	absPath, err := exec.LookPath(openssl)
	if err != nil {
		fmt.Printf("openssl LookPath error: %v\n", err)
	} else {
		_, _ = fmt.Printf("%s is available and the certificate %s will be displayed.\n", absPath, pemfile)
		// openssl x509 -inform 'pem' -in x.pem -text -out tmp
		cmd := exec.Command(absPath, "x509", "-inform", "PEM", "-in", path.Join(certsDir, pemfile), "-text", "-out", tmp)
		err = cmd.Run()
		if err != nil {
			fmt.Printf("openssl x509 Command Run error: %v\n", err)
			return
		}
		// Open the tmp certificate file and send to web browser line by line
		ftmp, err := os.Open(tmp)
		if err != nil {
			fmt.Printf("Open file %s error: %v\n", tmp, err)
		}
		defer ftmp.Close()
		bufscanner := bufio.NewScanner(ftmp)
		for bufscanner.Scan() {
			line := bufscanner.Text()
			_, err := fmt.Fprint(w, line)
			if err != nil {
				fmt.Printf("DisplayCertificate scanner error: %v\n", err)
			}
			fmt.Fprint(w, `<br \>`)
		}
	}
}

// Create the End-entity certificate and private key and store them in the receiver chain
func (chain *RSAChain) CreateEndEntity(w http.ResponseWriter) {
	// Create End-entity CA private key
	// Validate End-entity CA private key
	// Create End-entity CA cert using Intermediate CA as signer
	// Validate End-entity cert
	// Save PEM form of cert and private key, Save DER form of private key

	endEntityKey, err := rsa.GenerateKey(rand.Reader, chain.KeySizeEndEntity)
	if err != nil {
		log.Fatalf("rsa.GenerateKey for End-entity error: %v\n", err)
	}
	// Store the private key in the chain
	chain.endentityRSAkey = endEntityKey

	// Validate End-entity private key
	if err = endEntityKey.Validate(); err != nil {
		log.Fatalf("Validation of End-entity private key error: %v\n", err)
	}

	// Find the parent certificate depending on the number of intermediate CAs
	var parent *x509.Certificate
	var private *rsa.PrivateKey
	if chain.Inter2 != nil {
		parent = chain.Inter2
		private = chain.intermediate2RSAkey
	} else if chain.Inter1 != nil {
		parent = chain.Inter1
		private = chain.intermediate1RSAkey
	} else {
		parent = chain.Root
		private = chain.rootRSAkey
	}

	endEntityder, err := x509.CreateCertificate(rand.Reader, chain.EndEntity, parent, endEntityKey.Public(),
		private)
	if err != nil {
		log.Fatalf("End-entity CreateCertificate error: %v\n", err)
	}

	// Convert the Certificate from DER form
	endEntitycert, err := x509.ParseCertificate(endEntityder)
	if err != nil {
		log.Fatalf("End-entity error: %v\n", err)
	}
	// Store the certificate in the receiver chain
	chain.EndEntity = endEntitycert

	// Validate certificate
	err = parent.CheckSignature(endEntitycert.SignatureAlgorithm,
		endEntitycert.RawTBSCertificate, endEntitycert.Signature)
	if err != nil {
		fmt.Printf("End-entity CheckSignaure error: %v\n", err)
	}

	// Save End-entity private key in DER form
	f1, err := os.Create(path.Join(keysDir, "endEntitykey.der"))
	if err != nil {
		log.Fatalf("Create private key file %s error: %v\n", "endEntitykey.der", err)
	}
	defer f1.Close()

	endEntityKeyder := x509.MarshalPKCS1PrivateKey(endEntityKey)
	n, err := f1.Write(endEntityKeyder)
	if err != nil {
		log.Fatalf("End-entity key DER Write error: %v\n", err)
	}
	fmt.Printf("Wrote %d bytes to %v\n", n, "endEntitykey.der")

	// Save End-entity private key in PEM form
	f2, err := os.Create(path.Join(keysDir, "endEntitykey.pem"))
	if err != nil {
		log.Fatalf("Create End-entity private key file %s error: %v\n", "endEntitykey.pem", err)
	}

	endEntityKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: endEntityKeyder,
	}

	err = pem.Encode(f2, endEntityKeyBlock)
	if err != nil {
		log.Fatalf("End-entity private key PEM encode error: %v\n", err)
	}
	f2.Close()

	// Save End-entity certificate in PEM form
	f3, err := os.Create(path.Join(certsDir, "endEntity.pem"))
	if err != nil {
		log.Fatalf("Create End-entity certificate file %s error: %v\n", "endEntity.pem", err)
	}

	endEntityCertBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: endEntityder,
	}

	err = pem.Encode(f3, endEntityCertBlock)
	if err != nil {
		log.Fatalf("Write End-entity certificate %s error: %v\n", "endEntity.pem", err)
	}
	f3.Close()

	if f3, err = os.Open(path.Join(certsDir, "endEntity.pem")); err != nil {
		log.Fatalf("Open End-entity certificate %s error: %v\n", "endEntity.pem", err)
	}

	written, err := io.Copy(trustChainFile, f3)
	if err != nil {
		log.Fatalf("Write End-entity certificate to %s error: %v\n", trustChainPath, err)
	}
	f3.Close()
	// Go the end of the file
	trustChainFile.Seek(0, os.SEEK_END)
	fmt.Printf("Wrote %d bytes to %s\n", written, trustChainPath)

	// Display the certificate in web browser
	chain.DisplayCertificate("endEntity.pem", w)

	// Create Certificate Revocation List (CRL) for End-entity certificate
	templCRL := &x509.RevocationList{
		SignatureAlgorithm:  chain.EndEntity.SignatureAlgorithm,
		RevokedCertificates: []pkix.RevokedCertificate{},
		Number:              big.NewInt(time.Now().UnixNano()),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(365 * 24 * time.Hour),
	}
	endEntityCRLder, err := x509.CreateRevocationList(rand.Reader, templCRL, parent, private)
	if err != nil {
		log.Fatalf("End-entity CreateRevocationList error: %v\n", err)
	}

	// Save End-entity CRL in PEM form
	f4, err := os.Create(path.Join(crlDir, "endEntityCRL.crl"))
	if err != nil {
		log.Fatalf("Create End-entity CRL file %s error: %v\n", "endEntityCRL.crl", err)
	}
	defer f4.Close()

	endEntityCRLBlock := &pem.Block{
		Type:  "CRL",
		Bytes: endEntityCRLder,
	}

	err = pem.Encode(f4, endEntityCRLBlock)
	if err != nil {
		log.Fatalf("End-entity CRL PEM encode error: %v\n", err)
	}

	// Close trust chain file opened in Root CA certificate creation
	trustChainFile.Close()

	// Create pkcs12 file with certificates and private key using openssl pkcs12
	fileName := fmt.Sprintf("rsa%d.p12", chain.KeySizeEndEntity)
	absPath, err := exec.LookPath(openssl)
	if err != nil {
		fmt.Printf("openssl LookPath error: %v\n", err)
	} else {
		fmt.Printf("%s is available and a pkcs12 file will be created.\n", absPath)
		// openssl pkcs12 -export -descert -in ../../certs/trustChainRSA.pem -inkey ../../private/server.key -out ../../certs/rsa.p12
		cmd := exec.Command(absPath, "pkcs12", "-export", "-descert", "-in", path.Join(certsDir, trustChainPath),
			"-inkey", path.Join(keysDir, "endEntitykey.pem"), "-out", path.Join(certsDir, fileName), "-passout", "pass:12345")
		err = cmd.Run()
		if err != nil {
			fmt.Printf("openssl pkcs12 Command Run error: %v\n", err)
		}
	}
}

// Create the intermediate CA certificates and private keys and store them in the receiver chain
func (chain *RSAChain) CreateInterCA(w http.ResponseWriter) {
	// Create Intermediate CA private key
	// Validate Intermediate CA private key
	// Create Intermediate CA cert using Root CA as signer
	// Validate Intermediate cert
	// Save PEM form of cert and private key, Save DER form of private key

	// Create Intermediate1 if template exists
	if chain.Inter1 != nil {
		// Create RSA Intermediate1 CA private key
		inter1CAKey, err := rsa.GenerateKey(rand.Reader, chain.KeySizeInter1)
		if err != nil {
			log.Fatalf("rsa.GenerateKey for intermediate1 CA error: %v\n", err)
		}
		// Store the private key in the chain
		chain.intermediate1RSAkey = inter1CAKey

		// Validate Intermediate1 private key
		if err = inter1CAKey.Validate(); err != nil {
			log.Fatalf("Validation of intermediate1 CA private key error: %v\n", err)
		}

		inter1CAder, err := x509.CreateCertificate(rand.Reader, chain.Inter1, chain.Root, inter1CAKey.Public(),
			chain.rootRSAkey)
		if err != nil {
			log.Fatalf("Intermediate1 CreateCertificate error: %v\n", err)
		}

		// Convert the Certificate from DER form
		inter1CAcert, err := x509.ParseCertificate(inter1CAder)
		if err != nil {
			log.Fatalf("Intermediate1 CA ParseCertificates error: %v\n", err)
		}
		// Store the certificate in the receiver chain
		chain.Inter1 = inter1CAcert

		// Validate certificate
		err = chain.Root.CheckSignature(inter1CAcert.SignatureAlgorithm, inter1CAcert.RawTBSCertificate, inter1CAcert.Signature)
		if err != nil {
			fmt.Printf("Intermediate1 CheckSignaure error: %v\n", err)
		}

		// Save intermediate1 CA private key in DER form
		f1, err := os.Create(path.Join(keysDir, "inter1CAkey.der"))
		if err != nil {
			log.Fatalf("Create Inter1 CA private key file %s error: %v\n", "inter1CAkey.der", err)
		}
		defer f1.Close()

		inter1CAKeyder := x509.MarshalPKCS1PrivateKey(inter1CAKey)
		n, err := f1.Write(inter1CAKeyder)
		if err != nil {
			log.Fatalf("Intermediate1 CA key DER Write error: %v\n", err)
		}
		fmt.Printf("Wrote %d bytes to %v\n", n, "inter1CAkey.der")

		// Save intermediate1 CA private key in PEM form
		f2, err := os.Create(path.Join(keysDir, "inter1CAkey.pem"))
		if err != nil {
			log.Fatalf("Create Inter1 CA private key file %s error: %v\n", "inter1CAkey.pem", err)
		}
		defer f2.Close()

		inter1CAKeyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: inter1CAKeyder,
		}

		err = pem.Encode(f2, inter1CAKeyBlock)
		if err != nil {
			log.Fatalf("Intermediate1 CA key PEM encode error: %v\n", err)
		}

		// Save intermediate1 CA certificate in PEM form
		f3, err := os.Create(path.Join(certsDir, "inter1CA.pem"))
		if err != nil {
			log.Fatalf("Create CA certificate file %s error: %v\n", "inter1CA.pem", err)
		}

		inter1CACertBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: inter1CAder,
		}

		err = pem.Encode(f3, inter1CACertBlock)
		if err != nil {
			log.Fatalf("Write intermediate1 CA certificate to %s error: %v\n", "inter1CA.pem", err)
		}
		f3.Close()
		if f3, err = os.Open(path.Join(certsDir, "inter1CA.pem")); err != nil {
			log.Fatalf("Open intermediate1 CA certificate %s error: %v\n", "inter1CA.pem", err)
		}

		written, err := io.Copy(trustChainFile, f3)
		if err != nil {
			log.Fatalf("Write intermediate1 CA certificate to %s error: %v\n", trustChainPath, err)
		}
		f3.Close()
		fmt.Printf("Wrote %d bytes to %s\n", written, trustChainPath)
		// Go the end of the file
		trustChainFile.Seek(0, os.SEEK_END)

		// Display the certificate in the web browser
		chain.DisplayCertificate("inter1CA.pem", w)

		// Create Certificate Revocation List (CRL) for intermediate1 CA certificate
		templCRL := &x509.RevocationList{
			SignatureAlgorithm:  chain.Inter1.SignatureAlgorithm,
			RevokedCertificates: []pkix.RevokedCertificate{},
			Number:              big.NewInt(time.Now().UnixNano()),
			ThisUpdate:          time.Now(),
			NextUpdate:          time.Now().Add(365 * 24 * time.Hour),
		}
		inter1CACRLder, err := x509.CreateRevocationList(rand.Reader, templCRL, chain.Root, chain.rootRSAkey)
		if err != nil {
			log.Fatalf("Intermediate1 CA CreateRevocationList error: %v\n", err)
		}

		// Save intermediate1 CA CRL in PEM form
		f4, err := os.Create(path.Join(crlDir, "intermediate1CACRL.crl"))
		if err != nil {
			log.Fatalf("Create Intermediate1 CRL file %s error: %v\n", "intermediate1CACRL.crl", err)
		}
		defer f4.Close()

		inter1CACRLBlock := &pem.Block{
			Type:  "CRL",
			Bytes: inter1CACRLder,
		}

		err = pem.Encode(f4, inter1CACRLBlock)
		if err != nil {
			log.Fatalf("Intermediate1 CA CRL PEM encode error: %v\n", err)
		}
	}

	// Create Intermediate2 if template exists
	if chain.Inter2 != nil {
		// Create RSA Intermediate2 CA private key
		inter2CAKey, err := rsa.GenerateKey(rand.Reader, chain.KeySizeInter2)
		if err != nil {
			log.Fatalf("rsa.GenerateKey for intermediate CA error: %v\n", err)
		}
		// Store the private key in the chain
		chain.intermediate2RSAkey = inter2CAKey

		// Validate Intermediate2 private key
		if err = inter2CAKey.Validate(); err != nil {
			log.Fatalf("Validation of intermediate2 CA private key error: %v\n", err)
		}

		inter2CAder, err := x509.CreateCertificate(rand.Reader, chain.Inter2, chain.Inter1, inter2CAKey.Public(),
			chain.intermediate1RSAkey)
		if err != nil {
			log.Fatalf("Intermediate2 CreateCertificate error: %v\n", err)
		}

		// Convert the Certificate from DER form
		inter2CAcert, err := x509.ParseCertificate(inter2CAder)
		if err != nil {
			log.Fatalf("Intermediate CA ParseCertificates error: %v\n", err)
		}
		// Store the certificate in the receiver chain
		chain.Inter2 = inter2CAcert

		// Validate certificate
		err = chain.Inter1.CheckSignature(inter2CAcert.SignatureAlgorithm, inter2CAcert.RawTBSCertificate, inter2CAcert.Signature)
		if err != nil {
			fmt.Printf("Intermediate2 CheckSignaure error: %v\n", err)
		}

		// Save intermediate2 CA private key in DER form
		f1, err := os.Create(path.Join(keysDir, "inter2CAkey.der"))
		if err != nil {
			log.Fatalf("Create Inter2 CA private key file %s error: %v\n", "inter2CAkey.der", err)
		}
		defer f1.Close()

		inter2CAKeyder := x509.MarshalPKCS1PrivateKey(inter2CAKey)
		n, err := f1.Write(inter2CAKeyder)
		if err != nil {
			log.Fatalf("Intermediate2 CA key DER Write error: %v\n", err)
		}
		fmt.Printf("Wrote %d bytes to %v\n", n, "inter2CAkey.der")

		// Save intermediate2 CA private key in PEM form
		f2, err := os.Create(path.Join(keysDir, "inter2CAkey.pem"))
		if err != nil {
			log.Fatalf("Create Inter2 CA private key file %s error: %v\n", "inter2CAkey.pem", err)
		}
		defer f2.Close()

		inter2CAKeyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: inter2CAKeyder,
		}

		err = pem.Encode(f2, inter2CAKeyBlock)
		if err != nil {
			log.Fatalf("Intermediate2 CA key PEM encode error: %v\n", err)
		}

		// Save intermediate2 CA certificate in PEM form
		f3, err := os.Create(path.Join(certsDir, "inter2CA.pem"))
		if err != nil {
			log.Fatalf("Create Inter2 CA certificate file %s error: %v\n", "inter2CA.pem", err)
		}

		inter2CACertBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: inter2CAder,
		}

		err = pem.Encode(f3, inter2CACertBlock)
		if err != nil {
			log.Fatalf("Write intermediate2 CA certificate to %s error: %v\n", "inter2CA.pem", err)
		}
		f3.Close()
		if f3, err = os.Open(path.Join(certsDir, "inter2CA.pem")); err != nil {
			log.Fatalf("Open intermediate2 CA certificate %s error: %v\n", "inter2CA.pem", err)
		}

		written, err := io.Copy(trustChainFile, f3)
		if err != nil {
			log.Fatalf("Write intermediate2 CA certificate to %s error: %v\n", trustChainPath, err)
		}
		f3.Close()
		fmt.Printf("Wrote %d bytes to %s\n", written, trustChainPath)
		// Go the end of the file
		trustChainFile.Seek(0, os.SEEK_END)

		// Display the certificate
		chain.DisplayCertificate("inter2CA.pem", w)

		// Create Certificate Revocation List (CRL) for intermediate2 CA certificate
		templCRL := &x509.RevocationList{
			SignatureAlgorithm:  chain.Inter2.SignatureAlgorithm,
			RevokedCertificates: []pkix.RevokedCertificate{},
			Number:              big.NewInt(time.Now().UnixNano()),
			ThisUpdate:          time.Now(),
			NextUpdate:          time.Now().Add(365 * 24 * time.Hour),
		}
		inter2CACRLder, err := x509.CreateRevocationList(rand.Reader, templCRL, chain.Inter1, chain.intermediate1RSAkey)
		if err != nil {
			log.Fatalf("Intermediate2 CA CreateRevocationList error: %v\n", err)
		}

		// Save intermediate2 CA CRL in PEM form
		f4, err := os.Create(path.Join(crlDir, "intermediate2CACRL.crl"))
		if err != nil {
			log.Fatalf("Create Intermediate2 CRL file %s error: %v\n", "intermediate2CACRL.crl", err)
		}
		defer f4.Close()

		inter2CACRLBlock := &pem.Block{
			Type:  "CRL",
			Bytes: inter2CACRLder,
		}

		err = pem.Encode(f4, inter2CACRLBlock)
		if err != nil {
			log.Fatalf("Intermediate2 CA CRL PEM encode error: %v\n", err)
		}
	}
}

// Create the Root CA certificate and private key and store them in the receiver chain
func (chain *RSAChain) CreateRootCA(w http.ResponseWriter) {
	// Create Root CA private key
	// Validate Root CA private key
	// Create Root CA cert using Root CA as signer (self signed)
	// Validate Root cert
	// Save PEM form of cert and private key, Save DER form of private key

	// Create RSA Root CA private key
	rootCAKey, err := rsa.GenerateKey(rand.Reader, chain.KeySizeRoot)
	if err != nil {
		log.Fatalf("rsa.GenerateKey for root CA error: %v\n", err)
	}

	// Store the private key in the chain
	chain.rootRSAkey = rootCAKey

	// Validate Root private key
	if err = rootCAKey.Validate(); err != nil {
		log.Fatalf("Validation of root CA private key error: %v\n", err)
	}

	rootCAder, err := x509.CreateCertificate(rand.Reader, chain.Root, chain.Root, rootCAKey.Public(),
		rootCAKey)
	if err != nil {
		log.Fatalf("Root CreateCertificate error: %v\n", err)
	}

	// Convert the Certificate from DER form
	rootCAcert, err := x509.ParseCertificate(rootCAder)
	if err != nil {
		log.Fatalf("Root CA ParseCertificates error: %v\n", err)
	}
	// Store the certificate in the receiver chain
	chain.Root = rootCAcert

	// Validate certificate
	err = chain.Root.CheckSignature(rootCAcert.SignatureAlgorithm, rootCAcert.RawTBSCertificate, rootCAcert.Signature)
	if err != nil {
		log.Fatalf("Root CheckSignaure error: %v\n", err)
	}

	// Save root CA private key in DER form
	f1, err := os.Create(path.Join(keysDir, "rootCAkey.der"))
	if err != nil {
		log.Fatalf("Create CA private key file %s error: %v\n", "rootCAkey.der", err)
	}
	defer f1.Close()

	rootCAKeyder := x509.MarshalPKCS1PrivateKey(rootCAKey)
	n, err := f1.Write(rootCAKeyder)
	if err != nil {
		log.Fatalf("Root CA key DER Write error: %v\n", err)
	}
	fmt.Printf("Wrote %d bytes to %v\n", n, "rootCAkey.der")

	// Save root CA private key in PEM form
	f2, err := os.Create(path.Join(keysDir, "rootCAkey.pem"))
	if err != nil {
		log.Fatalf("Create CA private key file %s error: %v\n", "rootCAkey.pem", err)
	}
	defer f2.Close()

	rootCAKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: rootCAKeyder,
	}

	err = pem.Encode(f2, rootCAKeyBlock)
	if err != nil {
		log.Fatalf("Root CA key PEM encode error: %v\n", err)
	}

	// Save root CA certificate in PEM form
	f3, err := os.Create(path.Join(certsDir, "rootCA.pem"))
	if err != nil {
		log.Fatalf("Create CA certificate file %s error: %v\n", "rootCA.pem", err)
	}

	rootCACertBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCAder,
	}

	err = pem.Encode(f3, rootCACertBlock)
	if err != nil {
		log.Fatalf("Write root CA certificate %s error: %v\n", "rootCA.pem", err)
	}
	f3.Close()
	if f3, err = os.Open(path.Join(certsDir, "rootCA.pem")); err != nil {
		log.Fatalf("Open root CA certificate %s error: %v\n", "rootCA.pem", err)
	}

	// Create trust chain file with CAs and End-entity certs
	trustChainFile, err = os.Create(path.Join(certsDir, trustChainPath))
	if err != nil {
		log.Fatalf("Create trust chain file %s error: %v\n", trustChainPath, err)
	}

	written, err := io.Copy(trustChainFile, f3)
	if err != nil {
		log.Fatalf("Write root CA certificate to %s error: %v\n", trustChainPath, err)
	}
	f3.Close()
	fmt.Printf("Wrote %d bytes to %s\n", written, trustChainPath)
	// Go the end of the file
	trustChainFile.Seek(0, os.SEEK_END)

	// Display the certificate in the web browser
	chain.DisplayCertificate("rootCA.pem", w)

}

func GenerateCertChain(chain certchain.CertChain, w http.ResponseWriter) {
	fmt.Fprint(w, `<!DOCTYPE HTML>`)
	fmt.Fprint(w, `<html lang="eng">`)
	fmt.Fprint(w, `<head>`)
	fmt.Fprint(w, `<title>X509v3 Certificate Chain</title>`)
	fmt.Fprint(w, `<meta charset="utf-8" />`)
	fmt.Fprint(w, `<meta name="viewport" content="width=device-width, initial-scale=1.0" />`)
	fmt.Fprint(w, `</head>`)
	fmt.Fprint(w, `<body>`)
	fmt.Fprint(w, `<h2>RSA Certificate Chain</h2>`)

	// Create Root CA certificate and key
	chain.CreateRootCA(w)

	// Create the intermediate CA certificate and key
	chain.CreateInterCA(w)

	// Create the end-entity certificate and key
	chain.CreateEndEntity(w)

	fmt.Fprint(w, `</body>`)
	fmt.Fprint(w, `</html>`)
}
