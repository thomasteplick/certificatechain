// Common methods for certificate chain generation
// These are RSA and ECDSA key types
package certchain

import "net/http"

// CertChain dictates the methods that are needed to create certificate chains
type CertChain interface {
	CreateRootCA(w http.ResponseWriter)
	CreateInterCA(w http.ResponseWriter)
	CreateEndEntity(w http.ResponseWriter)
	DisplayCertificate(pemfile string, w http.ResponseWriter)
}
