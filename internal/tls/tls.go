package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
)

// Config holds TLS certificate checking configuration.
type Config struct {
	Timeout time.Duration
	Port    int
}

// tlsCheckParams represents the parameters for TLS certificate checks.
type tlsCheckParams struct {
	Domain       string `json:"domain"`
	Port         int    `json:"port,omitempty"`
	IncludeChain *bool  `json:"include_chain,omitempty"`
	CheckExpiry  *bool  `json:"check_expiry,omitempty"`
	ServerName   string `json:"server_name,omitempty"`
}

// CertificateInfo represents detailed information about a certificate.
type CertificateInfo struct {
	Subject            string            `json:"subject"`
	Issuer             string            `json:"issuer"`
	SerialNumber       string            `json:"serial_number"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	IsExpired          bool              `json:"is_expired"`
	ExpiresInDays      int               `json:"expires_in_days"`
	DNSNames           []string          `json:"dns_names"`
	IPAddresses        []string          `json:"ip_addresses"`
	EmailAddresses     []string          `json:"email_addresses"`
	URIs               []string          `json:"uris"`
	KeyUsage           []string          `json:"key_usage"`
	ExtKeyUsage        []string          `json:"ext_key_usage"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	PublicKeySize      int               `json:"public_key_size"`
	Version            int               `json:"version"`
	IsCA               bool              `json:"is_ca"`
	IsSelfSigned       bool              `json:"is_self_signed"`
	Extensions         map[string]string `json:"extensions"`
}

// CheckResult represents the result of a TLS certificate check.
type CheckResult struct {
	Domain           string            `json:"domain"`
	Port             int               `json:"port"`
	ServerName       string            `json:"server_name"`
	TLSVersion       string            `json:"tls_version"`
	CipherSuite      string            `json:"cipher_suite"`
	PeerCertificates []CertificateInfo `json:"peer_certificates"`
	ChainValid       bool              `json:"chain_valid"`
	ChainErrors      []string          `json:"chain_errors,omitempty"`
	ConnectionInfo   map[string]string `json:"connection_info"`
	Warnings         []string          `json:"warnings,omitempty"`
	CheckedAt        time.Time         `json:"checked_at"`
}

// HandleTLSCheck processes TLS certificate checks.
func HandleTLSCheck(_ context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params tlsCheckParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	// Validate required parameters
	if params.Domain == "" {
		return nil, fmt.Errorf("parameter \"domain\" is required")
	}

	// Set default port if not specified
	port := params.Port
	if port == 0 {
		port = 443
	}

	// Use domain as server name if not specified
	serverName := params.ServerName
	if serverName == "" {
		serverName = params.Domain
	}

	// Set default values for optional parameters
	if params.IncludeChain == nil {
		// Default to true if not specified
		includeChain := true
		params.IncludeChain = &includeChain
	}
	if params.CheckExpiry == nil {
		// Default to true if not specified
		checkExpiry := true
		params.CheckExpiry = &checkExpiry
	}

	// Validate domain format
	if strings.Contains(params.Domain, "..") || strings.HasPrefix(params.Domain, ".") {
		return nil, fmt.Errorf("invalid domain format: %q", params.Domain)
	}

	// Perform the TLS check
	result, err := checkTLSCertificate(params.Domain, port, serverName, config, params)
	if err != nil {
		return nil, fmt.Errorf("TLS check failed: %w", err)
	}

	return resp.JSON(result)
}

// checkTLSCertificate performs the actual TLS certificate check.
func checkTLSCertificate(domain string, port int, serverName string, config *Config, params tlsCheckParams) (*CheckResult, error) {
	// First attempt: try connecting with normal verification
	result, err := attemptTLSConnection(domain, port, serverName, config, params, false)
	if err != nil {
		// If the connection failed due to certificate validation,
		// try again with verification disabled to get certificate details for debugging
		if isCertificateValidationError(err) {
			debugResult, debugErr := attemptTLSConnection(domain, port, serverName, config, params, true)
			if debugErr == nil {
				// We got certificate details with verification disabled
				// Mark the chain as invalid and include the original error
				debugResult.ChainValid = false
				debugResult.ChainErrors = []string{err.Error()}
				debugResult.Warnings = append(debugResult.Warnings, "Certificate validation failed - details retrieved with verification disabled")
				return debugResult, nil
			}
		}
		return nil, err
	}

	return result, nil
}

// attemptTLSConnection attempts to connect and retrieve certificate information.
func attemptTLSConnection(domain string, port int, serverName string, config *Config, params tlsCheckParams, forceSkipVerify bool) (*CheckResult, error) {
	// Create TLS configuration
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: forceSkipVerify,
	}

	// Create a dialer with the context
	dialer := &net.Dialer{
		Timeout: config.Timeout,
	}

	// Connect to the server
	address := net.JoinHostPort(domain, strconv.Itoa(port))
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// Get connection state
	state := conn.ConnectionState()

	// Process peer certificates
	peerCerts := make([]CertificateInfo, 0, len(state.PeerCertificates))
	var warnings []string

	// Only process certificates if include_chain is enabled
	if *params.IncludeChain {
		for i, cert := range state.PeerCertificates {
			certInfo := processCertificate(cert)
			peerCerts = append(peerCerts, certInfo)

			// Add warnings for the server certificate if check_expiry is enabled
			if i == 0 && *params.CheckExpiry {
				if certInfo.IsExpired {
					warnings = append(warnings, "Server certificate is expired")
				} else if certInfo.ExpiresInDays <= 30 {
					warnings = append(warnings, fmt.Sprintf("Server certificate expires in %d days", certInfo.ExpiresInDays))
				}

				if certInfo.IsSelfSigned {
					warnings = append(warnings, "Server certificate is self-signed")
				}
			}
		}
	} else {
		// If include_chain is false, only include the server certificate
		if len(state.PeerCertificates) > 0 {
			certInfo := processCertificate(state.PeerCertificates[0])
			peerCerts = append(peerCerts, certInfo)

			// Add warnings for the server certificate if check_expiry is enabled
			if *params.CheckExpiry {
				if certInfo.IsExpired {
					warnings = append(warnings, "Server certificate is expired")
				} else if certInfo.ExpiresInDays <= 30 {
					warnings = append(warnings, fmt.Sprintf("Server certificate expires in %d days", certInfo.ExpiresInDays))
				}

				if certInfo.IsSelfSigned {
					warnings = append(warnings, "Server certificate is self-signed")
				}
			}
		}
	}

	// Check certificate chain validity (only if we're not forcing skip verify for debugging)
	chainValid := true
	var chainErrors []string

	if !forceSkipVerify {
		// Create a certificate pool for verification
		roots := x509.NewCertPool()
		if len(state.PeerCertificates) > 1 {
			for _, cert := range state.PeerCertificates[1:] {
				roots.AddCert(cert)
			}
		}

		// Verify the server certificate
		opts := x509.VerifyOptions{
			Roots:         roots,
			DNSName:       serverName,
			Intermediates: x509.NewCertPool(),
		}

		// Add intermediate certificates
		if len(state.PeerCertificates) > 1 {
			for _, cert := range state.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
		}

		if _, err := state.PeerCertificates[0].Verify(opts); err != nil {
			chainValid = false
			chainErrors = append(chainErrors, err.Error())
		}
	} else {
		// When forcing skip verify for debugging, we assume chain is invalid
		chainValid = false
	}

	// Get TLS version and cipher suite information
	tlsVersion := getTLSVersion(state.Version)
	cipherSuite := getCipherSuite(state.CipherSuite)

	// Create connection info
	connectionInfo := map[string]string{
		"negotiated_protocol": state.NegotiatedProtocol,
		"handshake_complete":  strconv.FormatBool(state.HandshakeComplete),
		"mutual_tls":          strconv.FormatBool(false), // We don't provide client certificates in this implementation
	}

	result := &CheckResult{
		Domain:           domain,
		Port:             port,
		ServerName:       serverName,
		TLSVersion:       tlsVersion,
		CipherSuite:      cipherSuite,
		PeerCertificates: peerCerts,
		ChainValid:       chainValid,
		ChainErrors:      chainErrors,
		ConnectionInfo:   connectionInfo,
		Warnings:         warnings,
		CheckedAt:        time.Now(),
	}

	return result, nil
}

// isCertificateValidationError checks if the error is related to certificate validation.
func isCertificateValidationError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "certificate has expired") ||
		strings.Contains(errStr, "certificate is not yet valid") ||
		strings.Contains(errStr, "certificate signed by unknown authority") ||
		strings.Contains(errStr, "certificate is not valid for") ||
		strings.Contains(errStr, "failed to verify certificate") ||
		strings.Contains(errStr, "x509:")
}

// processCertificate extracts detailed information from a certificate.
func processCertificate(cert *x509.Certificate) CertificateInfo {
	// Calculate days until expiry
	now := time.Now()
	expiresInDays := int(cert.NotAfter.Sub(now).Hours() / 24)

	// Extract IP addresses
	ipAddresses := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	// Extract URIs
	uris := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}

	// Extract key usage
	var keyUsage []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsage = append(keyUsage, "DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsage = append(keyUsage, "KeyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		keyUsage = append(keyUsage, "KeyAgreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsage = append(keyUsage, "CertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		keyUsage = append(keyUsage, "CRLSign")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		keyUsage = append(keyUsage, "DataEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		keyUsage = append(keyUsage, "ContentCommitment")
	}

	// Extract extended key usage
	var extKeyUsage []string
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			extKeyUsage = append(extKeyUsage, "Any")
		case x509.ExtKeyUsageServerAuth:
			extKeyUsage = append(extKeyUsage, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsage = append(extKeyUsage, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsage = append(extKeyUsage, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsage = append(extKeyUsage, "EmailProtection")
		case x509.ExtKeyUsageTimeStamping:
			extKeyUsage = append(extKeyUsage, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			extKeyUsage = append(extKeyUsage, "OCSPSigning")
		case x509.ExtKeyUsageIPSECEndSystem:
			extKeyUsage = append(extKeyUsage, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			extKeyUsage = append(extKeyUsage, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			extKeyUsage = append(extKeyUsage, "IPSECUser")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			extKeyUsage = append(extKeyUsage, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			extKeyUsage = append(extKeyUsage, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			extKeyUsage = append(extKeyUsage, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			extKeyUsage = append(extKeyUsage, "MicrosoftKernelCodeSigning")
		default:
			extKeyUsage = append(extKeyUsage, fmt.Sprintf("Unknown(%d)", usage))
		}
	}

	// Get public key size
	publicKeySize := getPublicKeySize(cert.PublicKey)

	// Check if self-signed
	isSelfSigned := cert.Subject.String() == cert.Issuer.String()

	// Process extensions
	extensions := make(map[string]string)
	for _, ext := range cert.Extensions {
		extensions[ext.Id.String()] = fmt.Sprintf("Critical: %v", ext.Critical)
	}

	return CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsExpired:          now.After(cert.NotAfter),
		ExpiresInDays:      expiresInDays,
		DNSNames:           cert.DNSNames,
		IPAddresses:        ipAddresses,
		EmailAddresses:     cert.EmailAddresses,
		URIs:               uris,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeySize:      publicKeySize,
		Version:            cert.Version,
		IsCA:               cert.IsCA,
		IsSelfSigned:       isSelfSigned,
		Extensions:         extensions,
	}
}

// getTLSVersion converts the TLS version constant to a string.
func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

// getCipherSuite returns the name of the cipher suite.
func getCipherSuite(cipherSuite uint16) string {
	switch cipherSuite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("Unknown (%#x)", cipherSuite)
	}
}

// getPublicKeySize returns the size of the public key in bits.
func getPublicKeySize(publicKey interface{}) int {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	default:
		return 0
	}
}
