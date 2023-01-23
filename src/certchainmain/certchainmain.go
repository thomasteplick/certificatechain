// Create a x509v3 certificate chain using either RSA or ECDSA keys.  The
// certificates and end-entity private key are bundled in a pkcs12 file.
// The individual PEM files are created as well.  This is the main package containing
// the main func.  The certificate chain consists of a root CA, zero, one, or
// two intermediate CAs, and an end entity certificate.  The root CA signs the
// first intermediate CA, which signs the second intermediate CA.  The last
// intermediate CA signs the end-entity certificate.

// This program is a web application which communicates with the user in
// a web browser.  This Go code is the backend software which forms the http
// server.  It creates the HTML file which is sent to the web browser.  The
// user enters certificate entries in a form and submits the form.  Any form
// errors are highlighted and returned to the user.  Upon successful submission
// of the form, the completed certificate chain is displayed in the web browser.
// A pkcs12 file is generated for deployment to a server.

package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thomasteplick/certchain"
	"github.com/thomasteplick/ecdsachain"
	"github.com/thomasteplick/rsachain"
)

const (
	addr           = "127.0.0.1:8080"                  // http server listen address
	fileForm       = "templates/certchainform.html"    // html for certificate chain form values
	fileDisplay    = "templates/certchaindisplay.html" // html for certificate chain display
	patternForm    = "/certchain"                      // http handler certificate form pattern
	patternDisplay = "/certchaindisplay"               // http handler certificate display pattern
)

// attributes for the HTML element
type Attribute struct {
	Text  string
	Error string
}

// global variables for html template parse and execution
var (
	tmplForm     *template.Template
	formControls map[string]Attribute = make(map[string]Attribute)
)

// Signature Algorithm map
var sigAlgoMap = map[string]x509.SignatureAlgorithm{
	"SHA256WithRSA":   x509.SHA256WithRSA,
	"SHA384WithRSA":   x509.SHA384WithRSA,
	"SHA512WithRSA":   x509.SHA512WithRSA,
	"ECDSAWithSHA256": x509.ECDSAWithSHA256,
	"ECDSAWithSHA384": x509.ECDSAWithSHA384,
	"ECDSAWithSHA512": x509.ECDSAWithSHA512,
}

// Key Usage map
var keyUsageMap = map[string]x509.KeyUsage{
	"DigitalSignature": x509.KeyUsageDigitalSignature,
	"KeyAgreement":     x509.KeyUsageKeyAgreement,
	"CertSign":         x509.KeyUsageCertSign,
	"CRLSign":          x509.KeyUsageCRLSign,
}

// Extended Key Usage map
var extKeyUsageMap = map[string]x509.ExtKeyUsage{

	"ServerAuth":  x509.ExtKeyUsageServerAuth,
	"ClientAuth":  x509.ExtKeyUsageClientAuth,
	"CodeSigning": x509.ExtKeyUsageCodeSigning,
	"IPSECTunnel": x509.ExtKeyUsageIPSECTunnel,
}

// ECDSA keysize to elliptic Curve map
var keysizeCurveMap = map[string]elliptic.Curve{
	"256": elliptic.P256(),
	"384": elliptic.P384(),
	"512": elliptic.P521(),
}

// init parses the html template files
func init() {
	tmplForm = template.Must(template.ParseFiles(fileForm))
}

// parseForm extracts the X509v3 data from http.Request
// and constructs a x509.Certificate template for either RSA or ECDSA keys.
func parseForm(r *http.Request) certchain.CertChain {
	// Extract the html form controls data for the x509v3 Certificates and keys
	// Validate the HTML x509v3 Form data and send back errors to client browser

	// HTML Form data valid

	if formControls["pubKeyAlgoRoot"].Text == "RSA" {
		integer, err := strconv.Atoi(formControls["keysizeRSARoot"].Text)
		if err != nil {
			log.Printf("Root RSA key size conversion error: %v\n", err)
			return nil
		}
		certRSA := rsachain.RSAChain{KeySizeRoot: integer, Inter1: nil, Inter2: nil}
		sigAlgorithm := sigAlgoMap[formControls["sigAlgoRSARoot"].Text]
		pubKeyAlg := x509.RSA
		// Create Root CA certificate
		version := 3
		max := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNum, err := rand.Int(rand.Reader, max)
		if err != nil {
			log.Fatalf("serialNum rand.Int error: %v\n", err)
		}
		subject := pkix.Name{
			Country:            []string{formControls["countryRoot"].Text},
			Province:           []string{formControls["stateRoot"].Text},
			Locality:           []string{formControls["localityRoot"].Text},
			Organization:       []string{formControls["orgRoot"].Text},
			OrganizationalUnit: []string{formControls["orgunitRoot"].Text},
			CommonName:         formControls["cnRoot"].Text,
		}
		issuer := subject
		notBefore := time.Now()
		integer, err = strconv.Atoi(formControls["validityRoot"].Text)
		if err != nil {
			log.Printf("Root validity (days) conversion error: %v\n", err)
			return nil
		}
		notAfter := notBefore.Add(time.Duration(integer) * 24 * time.Hour)

		var keyUsage x509.KeyUsage = 0
		for _, ku := range strings.Split(formControls["keyusageRoot"].Text, ",") {
			keyUsage |= keyUsageMap[ku]
		}

		isCA := true
		basicConstraintsValid := true
		crldp := []string{formControls["crldpRoot"].Text}
		ocspServer := []string{formControls["ocspRoot"].Text}

		sanIPAddresses := make([]net.IP, 0)
		for _, s := range []string{"san1Root", "san2Root", "san3Root", "san4Root", "san5Root"} {
			if len(formControls[s].Text) > 0 {
				ip := net.ParseIP(formControls[s].Text)
				if ip != nil {
					sanIPAddresses = append(sanIPAddresses, ip)
				} else {
					fmt.Printf("san IP address invalid: %v\n", formControls[s].Text)
				}
			}
		}

		var extKeyUsage []x509.ExtKeyUsage = make([]x509.ExtKeyUsage, 0)
		for _, eku := range strings.Split(formControls["extkeyusageRoot"].Text, ",") {
			if len(eku) > 0 {
				extKeyUsage = append(extKeyUsage, extKeyUsageMap[eku])
			}
		}
		//subjectKeyId   []byte
		//authorityKeyId []byte

		certRSA.Root = &x509.Certificate{
			SignatureAlgorithm:    sigAlgorithm,
			PublicKeyAlgorithm:    pubKeyAlg,
			Version:               version,
			SerialNumber:          serialNum,
			Issuer:                issuer,
			Subject:               subject,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              keyUsage,
			ExtKeyUsage:           extKeyUsage,
			IsCA:                  isCA,
			BasicConstraintsValid: basicConstraintsValid,
			IPAddresses:           sanIPAddresses,
			CRLDistributionPoints: crldp,
			OCSPServer:            ocspServer,
		}

		if formControls["numinterCAs"].Text == "1" || formControls["numinterCAs"].Text == "2" {
			integer, err := strconv.Atoi(formControls["keysizeRSAInter1"].Text)
			if err != nil {
				log.Printf("Inter1 RSA key size conversion error: %v\n", err)
				return nil
			}
			certRSA.KeySizeInter1 = integer
			sigAlgorithm := sigAlgoMap[formControls["sigAlgoRSAInter1"].Text]
			pubKeyAlg := x509.RSA
			// Create Inter1 CA certificate
			version := 3
			max := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNum, err := rand.Int(rand.Reader, max)
			if err != nil {
				log.Fatalf("serialNum rand.Int error: %v\n", err)
			}
			subject := pkix.Name{
				Country:            []string{formControls["countryInter1"].Text},
				Province:           []string{formControls["stateInter1"].Text},
				Locality:           []string{formControls["localityInter1"].Text},
				Organization:       []string{formControls["orgInter1"].Text},
				OrganizationalUnit: []string{formControls["orgunitInter1"].Text},
				CommonName:         formControls["cnInter1"].Text,
			}
			issuer := certRSA.Root.Subject
			notBefore := time.Now()
			integer, err = strconv.Atoi(formControls["validityInter1"].Text)
			if err != nil {
				log.Printf("Inter1 validity (days) conversion error: %v\n", err)
				return nil
			}
			notAfter := notBefore.Add(time.Duration(integer) * 24 * time.Hour)

			keyUsage = 0
			for _, ku := range strings.Split(formControls["keyusageInter1"].Text, ",") {
				keyUsage |= keyUsageMap[ku]
			}

			isCA := true
			basicConstraintsValid := true
			crldp := []string{formControls["crldpInter1"].Text}
			ocspServer := []string{formControls["ocspInter1"].Text}

			sanIPAddresses := make([]net.IP, 0)
			for _, s := range []string{"san1Inter1", "san2Inter1", "san3Inter1", "san4Inter1", "san5Inter1"} {
				if len(formControls[s].Text) > 0 {
					ip := net.ParseIP(formControls[s].Text)
					if ip != nil {
						sanIPAddresses = append(sanIPAddresses, ip)
					} else {
						fmt.Printf("san IP address invalid: %v\n", formControls[s].Text)
					}
				}
			}

			var extKeyUsage []x509.ExtKeyUsage = make([]x509.ExtKeyUsage, 0)
			for _, eku := range strings.Split(formControls["extkeyusageInter1"].Text, ",") {
				if len(eku) > 0 {
					extKeyUsage = append(extKeyUsage, extKeyUsageMap[eku])
				}
			}
			//subjectKeyId   []byte
			//authorityKeyId []byte

			certRSA.Inter1 = &x509.Certificate{
				SignatureAlgorithm:    sigAlgorithm,
				PublicKeyAlgorithm:    pubKeyAlg,
				Version:               version,
				SerialNumber:          serialNum,
				Issuer:                issuer,
				Subject:               subject,
				NotBefore:             notBefore,
				NotAfter:              notAfter,
				KeyUsage:              keyUsage,
				ExtKeyUsage:           extKeyUsage,
				IsCA:                  isCA,
				BasicConstraintsValid: basicConstraintsValid,
				IPAddresses:           sanIPAddresses,
				CRLDistributionPoints: crldp,
				OCSPServer:            ocspServer,
			}
		}

		if formControls["numinterCAs"].Text == "2" {
			integer, err := strconv.Atoi(formControls["keysizeRSAInter2"].Text)
			if err != nil {
				log.Printf("Inter2 RSA key size conversion error: %v\n", err)
				return nil
			}
			certRSA.KeySizeInter2 = integer
			sigAlgorithm := sigAlgoMap[formControls["sigAlgoRSAInter2"].Text]
			pubKeyAlg := x509.RSA
			// Create Inter2 CA certificate
			version := 3
			max := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNum, err := rand.Int(rand.Reader, max)
			if err != nil {
				log.Fatalf("serialNum rand.Int error: %v\n", err)
			}
			subject := pkix.Name{
				Country:            []string{formControls["countryInter2"].Text},
				Province:           []string{formControls["stateInter2"].Text},
				Locality:           []string{formControls["localityInter2"].Text},
				Organization:       []string{formControls["orgInter2"].Text},
				OrganizationalUnit: []string{formControls["orgunitInter2"].Text},
				CommonName:         formControls["cnInter2"].Text,
			}
			issuer := certRSA.Inter1.Subject
			notBefore := time.Now()
			integer, err = strconv.Atoi(formControls["validityInter2"].Text)
			if err != nil {
				log.Printf("Inter2 validity (days) conversion error: %v\n", err)
				return nil
			}
			notAfter := notBefore.Add(time.Duration(integer) * 24 * time.Hour)

			var keyUsage x509.KeyUsage = 0
			for _, ku := range strings.Split(formControls["keyusageInter2"].Text, ",") {
				keyUsage |= keyUsageMap[ku]
			}

			isCA := true
			basicConstraintsValid := true
			crldp := []string{formControls["crldpInter2"].Text}
			ocspServer := []string{formControls["ocspInter2"].Text}

			sanIPAddresses := make([]net.IP, 0)
			for _, s := range []string{"san1Inter2", "san2Inter2", "san3Inter2", "san4Inter2", "san5Inter2"} {
				if len(formControls[s].Text) > 0 {
					ip := net.ParseIP(formControls[s].Text)
					if ip != nil {
						sanIPAddresses = append(sanIPAddresses, ip)
					} else {
						fmt.Printf("san IP address invalid: %v\n", formControls[s].Text)
					}
				}
			}

			var extKeyUsage []x509.ExtKeyUsage = make([]x509.ExtKeyUsage, 0)
			for _, eku := range strings.Split(formControls["extkeyusageInter2"].Text, ",") {
				if len(eku) > 0 {
					extKeyUsage = append(extKeyUsage, extKeyUsageMap[eku])
				}
			}
			//subjectKeyId   []byte
			//authorityKeyId []byte

			certRSA.Inter2 = &x509.Certificate{
				SignatureAlgorithm:    sigAlgorithm,
				PublicKeyAlgorithm:    pubKeyAlg,
				Version:               version,
				SerialNumber:          serialNum,
				Issuer:                issuer,
				Subject:               subject,
				NotBefore:             notBefore,
				NotAfter:              notAfter,
				KeyUsage:              keyUsage,
				ExtKeyUsage:           extKeyUsage,
				IsCA:                  isCA,
				BasicConstraintsValid: basicConstraintsValid,
				IPAddresses:           sanIPAddresses,
				CRLDistributionPoints: crldp,
				OCSPServer:            ocspServer,
			}
		}

		// Create End-entity certificate
		integer, err = strconv.Atoi(formControls["keysizeRSAEndEntity"].Text)
		if err != nil {
			log.Printf("EndEntity RSA key size conversion error: %v\n", err)
			return nil
		}
		certRSA.KeySizeEndEntity = integer
		sigAlgorithm = sigAlgoMap[formControls["sigAlgoRSAEndEntity"].Text]
		pubKeyAlg = x509.RSA
		// Create EndEntity certificate
		version = 3
		max = new(big.Int).Lsh(big.NewInt(1), 128)
		serialNum, err = rand.Int(rand.Reader, max)
		if err != nil {
			log.Fatalf("serialNum rand.Int error: %v\n", err)
		}
		subject = pkix.Name{
			Country:            []string{formControls["countryEndEntity"].Text},
			Province:           []string{formControls["stateEndEntity"].Text},
			Locality:           []string{formControls["localityEndEntity"].Text},
			Organization:       []string{formControls["orgEndEntity"].Text},
			OrganizationalUnit: []string{formControls["orgunitEndEntity"].Text},
			CommonName:         formControls["cnEndEntity"].Text,
		}
		numinterCAs := formControls["numinterCAs"].Text
		if numinterCAs == "0" {
			issuer = certRSA.Root.Subject
		} else if numinterCAs == "1" {
			issuer = certRSA.Inter1.Subject
		} else {
			issuer = certRSA.Inter2.Subject
		}
		notBefore = time.Now()
		integer, err = strconv.Atoi(formControls["validityEndEntity"].Text)
		if err != nil {
			log.Printf("EndEntity validity (days) conversion error: %v\n", err)
			return nil
		}
		notAfter = notBefore.Add(time.Duration(integer) * 24 * time.Hour)

		keyUsage = 0
		for _, ku := range strings.Split(formControls["keyusageEndEntity"].Text, ",") {
			keyUsage |= keyUsageMap[ku]
		}

		isCA = false
		basicConstraintsValid = true
		crldp = []string{formControls["crldpEndEntity"].Text}
		ocspServer = []string{formControls["ocspEndEntity"].Text}

		sanIPAddresses = make([]net.IP, 0)
		for _, s := range []string{"san1EndEntity", "san2EndEntity", "san3EndEntity", "san4EndEntity", "san5EndEntity"} {
			if len(formControls[s].Text) > 0 {
				ip := net.ParseIP(formControls[s].Text)
				if ip != nil {
					sanIPAddresses = append(sanIPAddresses, ip)
				} else {
					fmt.Printf("san IP address invalid: %v\n", formControls[s].Text)
				}
			}
		}

		extKeyUsage = make([]x509.ExtKeyUsage, 0)
		for _, eku := range strings.Split(formControls["extkeyusageEndEntity"].Text, ",") {
			if len(eku) > 0 {
				extKeyUsage = append(extKeyUsage, extKeyUsageMap[eku])
			}
		}
		//subjectKeyId   []byte
		//authorityKeyId []byte

		certRSA.EndEntity = &x509.Certificate{
			SignatureAlgorithm:    sigAlgorithm,
			PublicKeyAlgorithm:    pubKeyAlg,
			Version:               version,
			SerialNumber:          serialNum,
			Issuer:                issuer,
			Subject:               subject,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              keyUsage,
			ExtKeyUsage:           extKeyUsage,
			IsCA:                  isCA,
			BasicConstraintsValid: basicConstraintsValid,
			IPAddresses:           sanIPAddresses,
			CRLDistributionPoints: crldp,
			OCSPServer:            ocspServer,
		}
		return &certRSA

	} else if formControls["pubKeyAlgoRoot"].Text == "ECDSA" {
		certECDSA := ecdsachain.ECDSAChain{CurveRoot: keysizeCurveMap[formControls["keysizeECDSARoot"].Text],
			Inter1: nil, Inter2: nil}
		sigAlgorithm := sigAlgoMap[formControls["sigAlgoECDSARoot"].Text]
		pubKeyAlg := x509.ECDSA
		// Create Root CA certificate
		version := 3
		max := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNum, err := rand.Int(rand.Reader, max)
		if err != nil {
			log.Fatalf("serialNum rand.Int error: %v\n", err)
		}
		subject := pkix.Name{
			Country:            []string{formControls["countryRoot"].Text},
			Province:           []string{formControls["stateRoot"].Text},
			Locality:           []string{formControls["localityRoot"].Text},
			Organization:       []string{formControls["orgRoot"].Text},
			OrganizationalUnit: []string{formControls["orgunitRoot"].Text},
			CommonName:         formControls["cnRoot"].Text,
		}
		issuer := subject
		notBefore := time.Now()
		integer, err := strconv.Atoi(formControls["validityRoot"].Text)
		if err != nil {
			log.Printf("Root validity (days) conversion error: %v\n", err)
			return nil
		}
		notAfter := notBefore.Add(time.Duration(integer) * 24 * time.Hour)
		var keyUsage x509.KeyUsage = 0
		for _, ku := range strings.Split(formControls["keyusageRoot"].Text, ",") {
			keyUsage |= keyUsageMap[ku]
		}

		isCA := true
		basicConstraintsValid := true
		crldp := []string{formControls["crldpRoot"].Text}
		ocspServer := []string{formControls["ocspRoot"].Text}

		sanIPAddresses := []net.IP{}
		for _, s := range []string{"san1Root", "san2Root", "san3Root", "san4Root", "san5Root"} {
			if len(formControls[s].Text) > 0 {
				ip := net.ParseIP(formControls[s].Text)
				if ip != nil {
					sanIPAddresses = append(sanIPAddresses, ip)
				} else {
					fmt.Printf("san IP address invalid: %v\n", formControls[s].Text)
				}
			}
		}

		var extKeyUsage []x509.ExtKeyUsage = make([]x509.ExtKeyUsage, 0)
		for _, eku := range strings.Split(formControls["extkeyusageRoot"].Text, ",") {
			if len(eku) > 0 {
				extKeyUsage = append(extKeyUsage, extKeyUsageMap[eku])
			}
		}
		//subjectKeyId   []byte
		//authorityKeyId []byte

		certECDSA.Root = &x509.Certificate{
			SignatureAlgorithm:    sigAlgorithm,
			PublicKeyAlgorithm:    pubKeyAlg,
			Version:               version,
			SerialNumber:          serialNum,
			Issuer:                issuer,
			Subject:               subject,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              keyUsage,
			ExtKeyUsage:           extKeyUsage,
			IsCA:                  isCA,
			BasicConstraintsValid: basicConstraintsValid,
			IPAddresses:           sanIPAddresses,
			CRLDistributionPoints: crldp,
			OCSPServer:            ocspServer,
		}

		if formControls["numinterCAs"].Text == "1" || formControls["numinterCAs"].Text == "2" {
			certECDSA.CurveInter1 = keysizeCurveMap[formControls["keysizeECDSAInter1"].Text]
			sigAlgorithm := sigAlgoMap[formControls["sigAlgoECDSAInter1"].Text]
			pubKeyAlg := x509.ECDSA
			// Create Intermediate1 CA certificate
			version = 3
			max := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNum, err := rand.Int(rand.Reader, max)
			if err != nil {
				log.Fatalf("serialNum rand.Int error: %v\n", err)
			}
			subject = pkix.Name{
				Country:            []string{formControls["countryInter1"].Text},
				Province:           []string{formControls["stateInter1"].Text},
				Locality:           []string{formControls["localityInter1"].Text},
				Organization:       []string{formControls["orgInter1"].Text},
				OrganizationalUnit: []string{formControls["orgunitInter1"].Text},
				CommonName:         formControls["cnInter1"].Text,
			}
			issuer := certECDSA.Root.Subject
			notBefore = time.Now()
			integer, err = strconv.Atoi(formControls["validityInter1"].Text)
			if err != nil {
				log.Printf("Inter1 validity (days) conversion error: %v\n", err)
				return nil
			}
			notAfter := notBefore.Add(time.Duration(integer) * 24 * time.Hour)
			keyUsage = 0
			for _, ku := range strings.Split(formControls["keyusageInter1"].Text, ",") {
				keyUsage |= keyUsageMap[ku]
			}

			isCA = true
			basicConstraintsValid = true
			crldp := []string{formControls["crldpInter1"].Text}
			ocspServer := []string{formControls["ocspInter1"].Text}

			sanIPAddresses := []net.IP{}
			for _, s := range []string{"san1Inter1", "san2Inter1", "san3Inter1", "san4Inter1", "san5Inter1"} {
				if len(formControls[s].Text) > 0 {
					ip := net.ParseIP(formControls[s].Text)
					if ip != nil {
						sanIPAddresses = append(sanIPAddresses, ip)
					} else {
						fmt.Printf("san IP address invalid: %v\n", formControls[s].Text)
					}
				}
			}

			var extKeyUsage []x509.ExtKeyUsage = make([]x509.ExtKeyUsage, 0)
			for _, eku := range strings.Split(formControls["extkeyusageInter1"].Text, ",") {
				if len(eku) > 0 {
					extKeyUsage = append(extKeyUsage, extKeyUsageMap[eku])
				}
			}
			//subjectKeyId   []byte
			//authorityKeyId []byte

			certECDSA.Inter1 = &x509.Certificate{
				SignatureAlgorithm:    sigAlgorithm,
				PublicKeyAlgorithm:    pubKeyAlg,
				Version:               version,
				SerialNumber:          serialNum,
				Issuer:                issuer,
				Subject:               subject,
				NotBefore:             notBefore,
				NotAfter:              notAfter,
				KeyUsage:              keyUsage,
				ExtKeyUsage:           extKeyUsage,
				IsCA:                  isCA,
				BasicConstraintsValid: basicConstraintsValid,
				IPAddresses:           sanIPAddresses,
				CRLDistributionPoints: crldp,
				OCSPServer:            ocspServer,
			}
		}

		if formControls["numinterCAs"].Text == "2" {
			certECDSA.CurveInter2 = keysizeCurveMap[formControls["keysizeECDSAInter2"].Text]
			sigAlgorithm := sigAlgoMap[formControls["sigAlgoECDSAInter2"].Text]
			pubKeyAlg := x509.ECDSA
			// Create Intermediate2 CA certificate
			version = 3
			max := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNum, err := rand.Int(rand.Reader, max)
			if err != nil {
				log.Fatalf("serialNum rand.Int error: %v\n", err)
			}
			subject = pkix.Name{
				Country:            []string{formControls["countryInter2"].Text},
				Province:           []string{formControls["stateInter2"].Text},
				Locality:           []string{formControls["localityInter2"].Text},
				Organization:       []string{formControls["orgInter2"].Text},
				OrganizationalUnit: []string{formControls["orgunitInter2"].Text},
				CommonName:         formControls["cnInter2"].Text,
			}
			issuer := certECDSA.Inter1.Subject
			notBefore = time.Now()
			integer, err = strconv.Atoi(formControls["validityInter2"].Text)
			if err != nil {
				log.Printf("Inter1 validity (days) conversion error: %v\n", err)
				return nil
			}
			notAfter := notBefore.Add(time.Duration(integer) * 24 * time.Hour)
			keyUsage = 0
			for _, ku := range strings.Split(formControls["keyusageInter2"].Text, ",") {
				keyUsage |= keyUsageMap[ku]
			}

			isCA = true
			basicConstraintsValid = true
			crldp := []string{formControls["crldpInter2"].Text}
			ocspServer := []string{formControls["ocspInter2"].Text}

			sanIPAddresses := []net.IP{}
			for _, s := range []string{"san1Inter2", "san2Inter2", "san3Inter2", "san4Inter2", "san5Inter2"} {
				if len(formControls[s].Text) > 0 {
					ip := net.ParseIP(formControls[s].Text)
					if ip != nil {
						sanIPAddresses = append(sanIPAddresses, ip)
					} else {
						fmt.Printf("san IP address invalid: %v\n", formControls[s].Text)
					}
				}
			}

			var extKeyUsage []x509.ExtKeyUsage = make([]x509.ExtKeyUsage, 0)
			for _, eku := range strings.Split(formControls["extkeyusageInter2"].Text, ",") {
				if len(eku) > 0 {
					extKeyUsage = append(extKeyUsage, extKeyUsageMap[eku])
				}
			}
			//subjectKeyId   []byte
			//authorityKeyId []byte

			certECDSA.Inter2 = &x509.Certificate{
				SignatureAlgorithm:    sigAlgorithm,
				PublicKeyAlgorithm:    pubKeyAlg,
				Version:               version,
				SerialNumber:          serialNum,
				Issuer:                issuer,
				Subject:               subject,
				NotBefore:             notBefore,
				NotAfter:              notAfter,
				KeyUsage:              keyUsage,
				ExtKeyUsage:           extKeyUsage,
				IsCA:                  isCA,
				BasicConstraintsValid: basicConstraintsValid,
				IPAddresses:           sanIPAddresses,
				CRLDistributionPoints: crldp,
				OCSPServer:            ocspServer,
			}
		}

		// Create End-entity certificate
		certECDSA.CurveEndEntity = keysizeCurveMap[formControls["keysizeECDSAEndEntity"].Text]
		sigAlgorithm = sigAlgoMap[formControls["sigAlgoECDSAEndEntity"].Text]
		pubKeyAlg = x509.ECDSA
		version = 3
		max = new(big.Int).Lsh(big.NewInt(1), 128)
		serialNum, err = rand.Int(rand.Reader, max)
		if err != nil {
			log.Fatalf("serialNum rand.Int error: %v\n", err)
		}
		subject = pkix.Name{
			Country:            []string{formControls["countryEndEntity"].Text},
			Province:           []string{formControls["stateEndEntity"].Text},
			Locality:           []string{formControls["localityEndEntity"].Text},
			Organization:       []string{formControls["orgEndEntity"].Text},
			OrganizationalUnit: []string{formControls["orgunitEndEntity"].Text},
			CommonName:         formControls["cnEndEntity"].Text,
		}
		numinterCAs := formControls["numinterCAs"].Text
		if numinterCAs == "0" {
			issuer = certECDSA.Root.Subject
		} else if numinterCAs == "1" {
			issuer = certECDSA.Inter1.Subject
		} else {
			issuer = certECDSA.Inter2.Subject
		}
		notBefore = time.Now()
		integer, err = strconv.Atoi(formControls["validityEndEntity"].Text)
		if err != nil {
			log.Printf("EndEntity validity (days) conversion error: %v\n", err)
			return nil
		}
		notAfter = notBefore.Add(time.Duration(integer) * 24 * time.Hour)

		keyUsage = 0
		for _, ku := range strings.Split(formControls["keyusageEndEntity"].Text, ",") {
			keyUsage |= keyUsageMap[ku]
		}

		isCA = false
		basicConstraintsValid = true
		crldp = []string{formControls["crldpEndEntity"].Text}
		ocspServer = []string{formControls["ocspEndEntity"].Text}

		sanIPAddresses = []net.IP{}
		for _, s := range []string{"san1EndEntity", "san2EndEntity", "san3EndEntity", "san4EndEntity", "san5EndEntity"} {
			if len(formControls[s].Text) > 0 {
				ip := net.ParseIP(formControls[s].Text)
				if ip != nil {
					sanIPAddresses = append(sanIPAddresses, ip)
				} else {
					fmt.Printf("san IP address invalid: %v\n", formControls[s].Text)
				}
			}
		}

		extKeyUsage = make([]x509.ExtKeyUsage, 0)
		for _, eku := range strings.Split(formControls["extkeyusageEndEntity"].Text, ",") {
			if len(eku) > 0 {
				extKeyUsage = append(extKeyUsage, extKeyUsageMap[eku])
			}
		}
		//subjectKeyId   []byte
		//authorityKeyId []byte

		certECDSA.EndEntity = &x509.Certificate{
			SignatureAlgorithm:    sigAlgorithm,
			PublicKeyAlgorithm:    pubKeyAlg,
			Version:               version,
			SerialNumber:          serialNum,
			Issuer:                issuer,
			Subject:               subject,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              keyUsage,
			ExtKeyUsage:           extKeyUsage,
			IsCA:                  isCA,
			BasicConstraintsValid: basicConstraintsValid,
			IPAddresses:           sanIPAddresses,
			CRLDistributionPoints: crldp,
			OCSPServer:            ocspServer,
		}

		return &certECDSA
	} else {
		return nil
	}
}

// HTTP handler to show initial <form> and a form that has errors (highlighted)
// HTML form submission is not complete at this point.
func handleCertChainForm(w http.ResponseWriter, r *http.Request) {

	// Regexp to find name="xxx" in html file.  Capture submatch "xxx"
	re := regexp.MustCompile(`name="(\S+)"\s+`)
	// map[string]string formControls stores html form element name attributes
	// Open fileForm and bufio scan each line for name attribute
	fread, err := os.Open(fileForm)
	if err != nil {
		log.Fatalf("Open %s error: %v\n", fileForm, err)
	}
	defer fread.Close()
	input := bufio.NewScanner(fread)
	for input.Scan() {
		line := input.Text()
		// check for name attribute in this line and insert into formControls map
		name := re.FindStringSubmatch(line)
		if name != nil {
			formControls[name[1]] = Attribute{}
		}
	}
	// Don't display Error Alert
	formControls["erroralert"] = Attribute{Error: "noerroralert", Text: ""}

	if err := tmplForm.Execute(w, formControls); err != nil {
		log.Fatalf("Write to HTTP output using template with grid error: %v\n", err)
	}

}

// verifyForm verifies HTML form entries and fills in formControls map
func verifyForm(r *http.Request, cert string) bool {

	result := true
	// All form controls
	/*
		"pubKeyAlgoRSA", "keysizeRSA", "sigAlgoRSA", "pubKeyAlgoECDSA", "keysizeECDSA",
		"sigAlgoECDSA", "validity", "country", "state", "org",
		"orgunit", "cn", "keyusage", "ca", "numinterCAs",
		"san1", "san2", "san3", "san4", "san5",
		"extkeyusage", "crldp", "ocsp"}
	*/
	subject := []string{"country", "state", "locality", "org", "orgunit", "cn"}

	misc2 := []string{"crldp", "ocsp"}

	san := []string{"san1", "san2", "san3", "san4", "san5"}

	switch cert {
	case "Root":
		if len(r.PostFormValue("ca"+cert)) == 0 {
			formControls["ca"+cert] = Attribute{Text: "", Error: "errornotext"}
			result = false
		}

		if r.PostFormValue("pubKeyAlgo"+cert) == "RSA" {
			formControls["pubKeyAlgo"+cert] = Attribute{Text: "RSA", Error: ""}
			if len(r.PostFormValue("keysizeRSA"+cert)) == 0 {
				formControls["keysizeRSA"+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls["keysizeRSA"+cert] = Attribute{Text: r.PostFormValue("keysizeRSA" + cert)}
			}
			if len(r.PostFormValue("sigAlgoRSA"+cert)) == 0 {
				formControls["sigAlgoRSA"+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls["sigAlgoRSA"+cert] = Attribute{Text: r.PostFormValue("sigAlgoRSA" + cert)}
			}
		} else if r.PostFormValue("pubKeyAlgo"+cert) == "ECDSA" {
			formControls["pubKeyAlgo"+cert] = Attribute{Text: "ECDSA", Error: ""}
			if len(r.PostFormValue("keysizeECDSA"+cert)) == 0 {
				formControls["keysizeECDSA"+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls["keysizeECDSA"+cert] = Attribute{Text: r.PostFormValue("keysizeECDSA" + cert)}
			}
			if len(r.PostFormValue("sigAlgoECDSA"+cert)) == 0 {
				formControls["sigAlgoECDSA"+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls["sigAlgoECDSA"+cert] = Attribute{Text: r.PostFormValue("sigAlgoECDSA" + cert), Error: ""}
			}
		} else {
			formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
			result = false
		}

		for _, subj := range subject {
			if len(r.PostFormValue(subj+cert)) == 0 {
				formControls[subj+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls[subj+cert] = Attribute{Text: r.PostFormValue(subj + cert), Error: ""}
			}
		}

		// Field required
		ku := r.PostForm["keyusage"+cert]
		if len(ku) == 0 {
			formControls["keyusage"+cert] = Attribute{Text: "", Error: "errornotext"}
			result = false
		} else {
			formControls["keyusage"+cert] = Attribute{Text: strings.Join(ku, ","), Error: ""}
		}

		// Field not required
		eku := r.PostForm["extkeyusage"+cert]
		if len(eku) > 0 {
			formControls["extkeyusage"+cert] = Attribute{Text: strings.Join(eku, ","), Error: ""}
		}

		// Field required
		if len(r.PostFormValue("validity"+cert)) == 0 {
			formControls["validity"+cert] = Attribute{Text: "", Error: "errornotext"}
			result = false
		} else {
			formControls["validity"+cert] = Attribute{Text: r.PostFormValue("validity" + cert), Error: ""}
		}

		// Field not required
		for _, ctrl := range misc2 {
			if len(r.PostFormValue(ctrl+cert)) > 0 {
				formControls[ctrl+cert] = Attribute{Text: r.PostFormValue(ctrl + cert), Error: ""}
			}
		}

		// Field not required
		for _, s := range san {
			if len(r.PostFormValue(s+cert)) > 0 {
				formControls[s+cert] = Attribute{Text: r.PostFormValue(s + cert), Error: ""}
			}
		}

	case "Inter":
		numinterCAs, err := strconv.Atoi(r.PostFormValue("numinterCAs"))
		if err != nil {
			formControls["numinterCAs"] = Attribute{Text: "", Error: "errornotext"}
			result = false
		} else {
			formControls["numinterCAs"] = Attribute{Text: r.PostFormValue("numinterCAs"), Error: ""}
			if numinterCAs == 1 || numinterCAs == 2 {
				// check for inter1
				cert := "Inter1"
				if r.PostFormValue("pubKeyAlgo"+cert) == "RSA" {
					formControls["pubkeyAlgo"+cert] = Attribute{Text: "RSA", Error: ""}
					if len(r.PostFormValue("keysizeRSA"+cert)) == 0 {
						formControls["keysizeRSA"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls["keysizeRSA"+cert] = Attribute{Text: r.PostFormValue("keysizeRSA" + cert), Error: ""}
					}
					if len(r.PostFormValue("sigAlgoRSA"+cert)) == 0 {
						formControls["sigAlgoRSA"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls["sigAlgoRSA"+cert] = Attribute{Text: r.PostFormValue("sigAlgoRSA" + cert), Error: ""}
					}
					if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoRoot") {
						formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					}
				} else if r.PostFormValue("pubKeyAlgo"+cert) == "ECDSA" {
					formControls["pubkeyAlgo"+cert] = Attribute{Text: "ECDSA", Error: ""}
					if len(r.PostFormValue("keysizeECDSA"+cert)) == 0 {
						formControls["keysizeECDSA"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls["keysizeECDSA"+cert] = Attribute{Text: r.PostFormValue("keysizeECDSA" + cert), Error: ""}
					}
					if len(r.PostFormValue("sigAlgoECDSA"+cert)) == 0 {
						formControls["sigAlgoECDSA"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls["sigAlgoECDSA"+cert] = Attribute{Text: r.PostFormValue("sigAlgoECDSA" + cert), Error: ""}
					}
					if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoRoot") {
						formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					}
				} else {
					formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}

				for _, subj := range subject {
					if len(r.PostFormValue(subj+cert)) == 0 {
						formControls[subj+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls[subj+cert] = Attribute{Text: r.PostFormValue(subj + cert), Error: ""}
					}
				}

				// Field required
				ku := r.PostForm["keyusage"+cert]
				if len(ku) == 0 {
					formControls["keyusage"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				} else {
					formControls["keyusage"+cert] = Attribute{Text: strings.Join(ku, ","), Error: ""}
				}

				// Field not required
				eku := r.PostForm["extkeyusage"+cert]
				if len(eku) > 0 {
					formControls["extkeyusage"+cert] = Attribute{Text: strings.Join(eku, ","), Error: ""}
				}

				// Field required
				if len(r.PostFormValue("validity"+cert)) == 0 {
					formControls["validity"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				} else {
					formControls["validity"+cert] = Attribute{Text: r.PostFormValue("validity" + cert), Error: ""}
				}

				// Field not required
				for _, ctrl := range misc2 {
					if len(r.PostFormValue(ctrl+cert)) > 0 {
						formControls[ctrl+cert] = Attribute{Text: r.PostFormValue(ctrl + cert), Error: ""}
					}
				}

				// Field not required
				for _, s := range san {
					if len(r.PostFormValue(s+cert)) > 0 {
						formControls[s+cert] = Attribute{Text: r.PostFormValue(s + cert), Error: ""}
					}
				}

				if len(r.PostFormValue("ca"+cert)) == 0 {
					formControls["ca"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}
			}
			if numinterCAs == 2 {
				// check for inter2
				cert := "Inter2"
				if r.PostFormValue("pubKeyAlgo"+cert) == "RSA" {
					formControls["pubkeyAlgo"+cert] = Attribute{Text: "RSA", Error: ""}
					if len(r.PostFormValue("keysizeRSA"+cert)) == 0 {
						formControls["keysizeRSA"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls["keysizeRSA"+cert] = Attribute{Text: r.PostFormValue("keysizeRSA" + cert), Error: ""}
					}
					if len(r.PostFormValue("sigAlgoRSA"+cert)) == 0 {
						formControls["sigAlgoRSA"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls["sigAlgoRSA"+cert] = Attribute{Text: r.PostFormValue("sigAlgoRSA" + cert), Error: ""}
					}
					if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoInter1") {
						formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					}
				} else if r.PostFormValue("pubKeyAlgo"+cert) == "ECDSA" {
					formControls["pubkeyAlgo"+cert] = Attribute{Text: "ECDSA", Error: ""}
					if len(r.PostFormValue("keysizeECDSA"+cert)) == 0 {
						formControls["keysizeECDSA"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls["keysizeECDSA"+cert] = Attribute{Text: r.PostFormValue("keysizeECDSA" + cert), Error: ""}
					}
					if len(r.PostFormValue("sigAlgoECDSA"+cert)) == 0 {
						formControls["sigAlgoECDSA"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls["sigAlgoECDSA"+cert] = Attribute{Text: r.PostFormValue("sigAlgoECDSA" + cert), Error: ""}
					}
					if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoInter1") {
						formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					}
				} else {
					formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}

				for _, subj := range subject {
					if len(r.PostFormValue(subj+cert)) == 0 {
						formControls[subj+cert] = Attribute{Text: "", Error: "errornotext"}
						result = false
					} else {
						formControls[subj+cert] = Attribute{Text: r.PostFormValue(subj + cert), Error: ""}
					}
				}

				// Field required
				ku := r.PostForm["keyusage"+cert]
				if len(ku) == 0 {
					formControls["keyusage"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				} else {
					formControls["keyusage"+cert] = Attribute{Text: strings.Join(ku, ","), Error: ""}
				}

				// Field not required
				eku := r.PostForm["extkeyusage"+cert]
				if len(eku) > 0 {
					formControls["extkeyusage"+cert] = Attribute{Text: strings.Join(eku, ","), Error: ""}
				}

				// Field required
				if len(r.PostFormValue("validity"+cert)) == 0 {
					formControls["validity"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				} else {
					formControls["validity"+cert] = Attribute{Text: r.PostFormValue("validity" + cert), Error: ""}
				}

				// Field not required
				for _, ctrl := range misc2 {
					if len(r.PostFormValue(ctrl+cert)) > 0 {
						formControls[ctrl+cert] = Attribute{Text: r.PostFormValue(ctrl + cert), Error: ""}
					}
				}

				// Field not required
				for _, s := range san {
					if len(r.PostFormValue(s+cert)) > 0 {
						formControls[s+cert] = Attribute{Text: r.PostFormValue(s + cert), Error: ""}
					}
				}

				if len(r.PostFormValue("ca"+cert)) == 0 {
					formControls["ca"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}
			}
		}
	case "EndEntity":
		if len(r.PostFormValue("ca"+cert)) > 0 {
			formControls["ca"+cert] = Attribute{Text: "", Error: "errornotext"}
			result = false
		}

		if r.PostFormValue("pubKeyAlgo"+cert) == "RSA" {
			formControls["pubKeyAlgo"+cert] = Attribute{Text: "RSA"}
			if len(r.PostFormValue("keysizeRSA"+cert)) == 0 {
				formControls["keysizeRSA"+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls["keysizeRSA"+cert] = Attribute{Text: r.PostFormValue("keysizeRSA" + cert)}
			}
			if len(r.PostFormValue("sigAlgoRSA"+cert)) == 0 {
				formControls["sigAlgoRSA"+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls["sigAlgoRSA"+cert] = Attribute{Text: r.PostFormValue("sigAlgoRSA" + cert)}
			}

			switch r.PostFormValue("numinterCAs") {
			case "0":
				if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoRoot") {
					formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}
			case "1":
				if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoInter1") {
					formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}
			case "2":
				if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoInter2") {
					formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}
			}
		} else if r.PostFormValue("pubKeyAlgo"+cert) == "ECDSA" {
			formControls["pubKeyAlgo"+cert] = Attribute{Text: "ECDSA"}
			if len(r.PostFormValue("keysizeECDSA"+cert)) == 0 {
				formControls["keysizeECDSA"+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls["keysizeECDSA"+cert] = Attribute{Text: r.PostFormValue("keysizeECDSA" + cert)}
			}
			if len(r.PostFormValue("sigAlgoECDSA"+cert)) == 0 {
				formControls["sigAlgoECDSA"+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls["sigAlgoECDSA"+cert] = Attribute{Text: r.PostFormValue("sigAlgoECDSA" + cert)}
			}

			switch r.PostFormValue("numinterCAs") {
			case "0":
				if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoRoot") {
					formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}
			case "1":
				if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoInter1") {
					formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}
			case "2":
				if r.PostFormValue("pubKeyAlgo"+cert) != r.PostFormValue("pubKeyAlgoInter2") {
					formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
					result = false
				}
			}
		} else {
			formControls["pubKeyAlgo"+cert] = Attribute{Text: "", Error: "errornotext"}
			result = false
		}

		for _, subj := range subject {
			if len(r.PostFormValue(subj+cert)) == 0 {
				formControls[subj+cert] = Attribute{Text: "", Error: "errornotext"}
				result = false
			} else {
				formControls[subj+cert] = Attribute{Text: r.PostFormValue(subj + cert), Error: ""}
			}
		}

		// Field required
		ku := r.PostForm["keyusage"+cert]
		if len(ku) == 0 {
			formControls["keyusage"+cert] = Attribute{Text: "", Error: "errornotext"}
			result = false
		} else {
			formControls["keyusage"+cert] = Attribute{Text: strings.Join(ku, ","), Error: ""}
		}

		// Field not required
		eku := r.PostForm["extkeyusage"+cert]
		if len(eku) > 0 {
			formControls["extkeyusage"+cert] = Attribute{Text: strings.Join(eku, ","), Error: ""}
		}

		// Field required
		if len(r.PostFormValue("validity"+cert)) == 0 {
			formControls["validity"+cert] = Attribute{Text: "", Error: "errornotext"}
			result = false
		} else {
			formControls["validity"+cert] = Attribute{Text: r.PostFormValue("validity" + cert), Error: ""}
		}

		// Field not required
		for _, ctrl := range misc2 {
			if len(r.PostFormValue(ctrl+cert)) > 0 {
				formControls[ctrl+cert] = Attribute{Text: r.PostFormValue(ctrl + cert), Error: ""}
			}
		}

		// Field not required
		for _, s := range san {
			if len(r.PostFormValue(s+cert)) > 0 {
				formControls[s+cert] = Attribute{Text: r.PostFormValue(s + cert), Error: ""}
			}
		}

	default:
		log.Fatalln("Invalid certificate type passed to verifyForm().")
	}

	// Display the error alert message
	if !result {
		formControls["erroralert"] = Attribute{Error: "erroralert", Text: ""}
	}

	return result

}

// HTTP handler to process and display the certificate chain after successful <form> submission (no errors)
func handleCertChainDisplay(w http.ResponseWriter, r *http.Request) {
	// Loop over formControls and insert values into Request.FormValue(key).
	// Determine if any form value errors, mark class="certerror", CSS rule for background-color: red.
	// If the HTML form has errors, execute tmplForm with formControls.

	err := r.ParseForm()
	if err != nil {
		log.Fatalf("Parsing HTTP form error: %v\n", err)
	}

	// Verify Root CA has key type, size, signature algorithm, validity, subject fields,
	// key usage, and ca with non-empty values.
	rootOK := verifyForm(r, "Root")
	fmt.Printf("rootOK = %t\n", rootOK)

	// Verify number of intermediate CAs.  If one intermediate CA, verify Inter1 has
	// key type, size, signature algorithm, validity, subject fields, key usage,
	// and ca with non-empty values.  If two intermediate CAs, verify Inter1 and Inter2 have
	// non-values values for those fields.
	intermediateOK := verifyForm(r, "Inter")
	fmt.Printf("intermediateOK = %t\n", intermediateOK)

	// Verify End-entity certificate has key type, size, signature algorithm, validity, subject fields,
	// key usage, and extended key usage with non-empty values. Verify ca is empty.
	endentityOK := verifyForm(r, "EndEntity")
	fmt.Printf("endentityOK = %t\n", endentityOK)

	// If errors send form back with highlighted errors
	if !rootOK || !intermediateOK || !endentityOK {
		fmt.Println("Form has errors.")
		if err := tmplForm.Execute(w, formControls); err != nil {
			log.Fatalf("Write to HTTP output using template with grid error: %v\n", err)
		}
		// Form has no errors
	} else {
		fmt.Println("Form has no errors.")
		// else HTML Form data valid
		// Create the Certificate Chain
		chain := parseForm(r)
		chainRSA, ok := chain.(*rsachain.RSAChain)
		if ok {
			rsachain.GenerateCertChain(chainRSA, w)
		} else {
			chainECDSA, ok := chain.(*ecdsachain.ECDSAChain)
			if ok {
				ecdsachain.GenerateCertChain(chainECDSA, w)
			} else {
				log.Fatalf("parseForm did not return chainRSA or chainECDSA\n")
			}
		}
	}
}

// Register the HTTP handlers, listen on the interface, and serve clients
func main() {
	// Initialize formControls with keys found in fileForm

	// Setup http server with handlers for certificate chain HTML form values and display
	http.HandleFunc(patternForm, handleCertChainForm)
	http.HandleFunc(patternDisplay, handleCertChainDisplay)
	fmt.Printf("Certificate Chain Server listening on %v.\n", addr)
	http.ListenAndServe(addr, nil)
}
