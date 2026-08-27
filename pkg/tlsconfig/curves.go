// Package tlsconfig pins the cluster-wide TLS 1.3 curve preference list.
package tlsconfig

import "crypto/tls"

// Curves is the fixed TLS 1.3 curve allowlist: two ML-KEM hybrids (PQ-capable
// peers always negotiate these) followed by two classical fallbacks for SDKs
// without ML-KEM.
var Curves = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP384r1MLKEM1024,
	tls.X25519,
	tls.CurveP384,
}
