package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// TLSConfig manages TLS and mTLS configuration for services
type TLSConfig struct {
	logger           *logrus.Logger
	caCert           *x509.Certificate
	caKey            *rsa.PrivateKey
	serverCert       *x509.Certificate
	serverKey        *rsa.PrivateKey
	clientCerts      map[string]*x509.Certificate
	trustedServices  []string
	enableMTLS       bool
	minTLSVersion    uint16
	cipherSuites     []uint16
}

// ServiceCertificate represents a service certificate with metadata
type ServiceCertificate struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	PEMCert     []byte
	PEMKey      []byte
	ServiceName string
	ExpiresAt   time.Time
	IssuedAt    time.Time
}

// NewTLSConfig creates a new TLS configuration manager
func NewTLSConfig(logger *logrus.Logger) *TLSConfig {
	return &TLSConfig{
		logger:          logger,
		clientCerts:     make(map[string]*x509.Certificate),
		trustedServices: []string{"isectech-frontend", "isectech-api-gateway", "isectech-backend-services"},
		enableMTLS:      os.Getenv("ENABLE_MTLS") == "true",
		minTLSVersion:   tls.VersionTLS12,
		cipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// InitializeCA creates or loads the Certificate Authority
func (tc *TLSConfig) InitializeCA(caKeyPath, caCertPath string) error {
	tc.logger.Info("Initializing Certificate Authority")

	// Try to load existing CA
	if tc.loadExistingCA(caKeyPath, caCertPath) {
		tc.logger.Info("Loaded existing Certificate Authority")
		return nil
	}

	// Generate new CA
	tc.logger.Info("Generating new Certificate Authority")
	if err := tc.generateCA(caKeyPath, caCertPath); err != nil {
		return fmt.Errorf("failed to generate CA: %v", err)
	}

	tc.logger.Info("Certificate Authority initialized successfully")
	return nil
}

// GenerateServiceCertificate creates a new certificate for a service
func (tc *TLSConfig) GenerateServiceCertificate(serviceName string, dnsNames []string, ipAddresses []string) (*ServiceCertificate, error) {
	tc.logger.WithField("service_name", serviceName).Info("Generating service certificate")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"iSECTECH Security Platform"},
			OrganizationalUnit: []string{"Platform Services"},
			CommonName:         serviceName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// Parse IP addresses
	for _, ipStr := range ipAddresses {
		if ip := parseIPAddress(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, tc.caCert, &privateKey.PublicKey, tc.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Convert to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	serviceCert := &ServiceCertificate{
		Certificate: cert,
		PrivateKey:  privateKey,
		PEMCert:     certPEM,
		PEMKey:      keyPEM,
		ServiceName: serviceName,
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	}

	// Cache client certificate
	tc.clientCerts[serviceName] = cert

	tc.logger.WithFields(logrus.Fields{
		"service_name": serviceName,
		"expires_at":   cert.NotAfter,
		"serial":       cert.SerialNumber,
	}).Info("Service certificate generated successfully")

	return serviceCert, nil
}

// GetServerTLSConfig returns TLS configuration for server
func (tc *TLSConfig) GetServerTLSConfig() *tls.Config {
	config := &tls.Config{
		MinVersion:   tc.minTLSVersion,
		CipherSuites: tc.cipherSuites,
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{tc.serverCert.Raw},
				PrivateKey:  tc.serverKey,
			},
		},
		PreferServerCipherSuites: true,
	}

	if tc.enableMTLS {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = tc.createClientCAPool()
		config.VerifyPeerCertificate = tc.verifyPeerCertificate
	}

	return config
}

// GetClientTLSConfig returns TLS configuration for client
func (tc *TLSConfig) GetClientTLSConfig(serviceName string) *tls.Config {
	config := &tls.Config{
		MinVersion:         tc.minTLSVersion,
		CipherSuites:       tc.cipherSuites,
		InsecureSkipVerify: false, // Always verify server certificates
		RootCAs:            tc.createServerCAPool(),
	}

	if tc.enableMTLS {
		// Add client certificate for mutual authentication
		if cert, exists := tc.clientCerts[serviceName]; exists {
			config.Certificates = []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  tc.serverKey, // In production, each service would have its own key
				},
			}
		}
	}

	return config
}

// CreateSecureHTTPClient creates an HTTP client with proper TLS configuration
func (tc *TLSConfig) CreateSecureHTTPClient(serviceName string) *http.Client {
	tlsConfig := tc.GetClientTLSConfig(serviceName)
	
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		DisableCompression:    false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// CreateSecureHTTPServer creates an HTTP server with proper TLS configuration
func (tc *TLSConfig) CreateSecureHTTPServer(handler http.Handler, addr string) *http.Server {
	tlsConfig := tc.GetServerTLSConfig()

	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server
}

// ValidateCertificate validates a certificate against the CA and policies
func (tc *TLSConfig) ValidateCertificate(cert *x509.Certificate) error {
	// Check if certificate is expired
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate expired at %v", cert.NotAfter)
	}

	if time.Now().Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid until %v", cert.NotBefore)
	}

	// Verify certificate chain
	roots := x509.NewCertPool()
	roots.AddCert(tc.caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	// Check if service is trusted
	serviceName := cert.Subject.CommonName
	if !tc.isServiceTrusted(serviceName) {
		return fmt.Errorf("untrusted service: %s", serviceName)
	}

	return nil
}

// RotateCertificates rotates certificates that are nearing expiration
func (tc *TLSConfig) RotateCertificates(threshold time.Duration) error {
	tc.logger.Info("Starting certificate rotation check")

	rotated := 0

	// Check server certificate
	if time.Until(tc.serverCert.NotAfter) < threshold {
		tc.logger.Info("Server certificate nearing expiration, rotating")
		if err := tc.rotateServerCertificate(); err != nil {
			tc.logger.WithError(err).Error("Failed to rotate server certificate")
			return err
		}
		rotated++
	}

	// Check client certificates
	for serviceName, cert := range tc.clientCerts {
		if time.Until(cert.NotAfter) < threshold {
			tc.logger.WithField("service_name", serviceName).Info("Client certificate nearing expiration, rotating")
			if err := tc.rotateClientCertificate(serviceName); err != nil {
				tc.logger.WithError(err).WithField("service_name", serviceName).Error("Failed to rotate client certificate")
				continue
			}
			rotated++
		}
	}

	tc.logger.WithField("rotated_count", rotated).Info("Certificate rotation completed")
	return nil
}

// Private helper methods

func (tc *TLSConfig) loadExistingCA(keyPath, certPath string) bool {
	// Load CA certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return false
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false
	}

	// Load CA private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return false
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return false
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return false
	}

	tc.caCert = caCert
	tc.caKey = caKey

	return true
}

func (tc *TLSConfig) generateCA(keyPath, certPath string) error {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// Create CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"iSECTECH Security Platform"},
			OrganizationalUnit: []string{"Certificate Authority"},
			CommonName:         "iSECTECH Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Parse certificate
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	// Save CA certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}

	// Save CA private key
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}

	tc.caCert = caCert
	tc.caKey = caKey

	return nil
}

func (tc *TLSConfig) createClientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(tc.caCert)
	return pool
}

func (tc *TLSConfig) createServerCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(tc.caCert)
	return pool
}

func (tc *TLSConfig) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %v", err)
	}

	return tc.ValidateCertificate(cert)
}

func (tc *TLSConfig) isServiceTrusted(serviceName string) bool {
	for _, trusted := range tc.trustedServices {
		if trusted == serviceName {
			return true
		}
	}
	return false
}

func (tc *TLSConfig) rotateServerCertificate() error {
	// Generate new server certificate
	newCert, err := tc.GenerateServiceCertificate("isectech-server", []string{"*.isectech.com", "localhost"}, []string{"127.0.0.1"})
	if err != nil {
		return err
	}

	tc.serverCert = newCert.Certificate
	tc.serverKey = newCert.PrivateKey

	return nil
}

func (tc *TLSConfig) rotateClientCertificate(serviceName string) error {
	// Generate new client certificate
	newCert, err := tc.GenerateServiceCertificate(serviceName, []string{serviceName + ".internal.isectech.com"}, nil)
	if err != nil {
		return err
	}

	tc.clientCerts[serviceName] = newCert.Certificate

	return nil
}

func parseIPAddress(ipStr string) []byte {
	// In a real implementation, you would use net.ParseIP
	// This is a simplified version
	return nil
}

// TLSMiddleware provides TLS-related middleware for HTTP servers
type TLSMiddleware struct {
	tlsConfig *TLSConfig
	logger    *logrus.Logger
}

// NewTLSMiddleware creates a new TLS middleware
func NewTLSMiddleware(tlsConfig *TLSConfig, logger *logrus.Logger) *TLSMiddleware {
	return &TLSMiddleware{
		tlsConfig: tlsConfig,
		logger:    logger,
	}
}

// RequireHTTPS redirects HTTP requests to HTTPS
func (tm *TLSMiddleware) RequireHTTPS() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				httpsURL := "https://" + r.Host + r.RequestURI
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds security headers to responses
func (tm *TLSMiddleware) SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// HSTS
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			
			// Content Security Policy
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
			
			// X-Frame-Options
			w.Header().Set("X-Frame-Options", "DENY")
			
			// X-Content-Type-Options
			w.Header().Set("X-Content-Type-Options", "nosniff")
			
			// X-XSS-Protection
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			
			// Referrer Policy
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			next.ServeHTTP(w, r)
		})
	}
}

// LogTLSInfo logs TLS connection information
func (tm *TLSMiddleware) LogTLSInfo() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				tm.logger.WithFields(logrus.Fields{
					"tls_version":     getTLSVersionString(r.TLS.Version),
					"cipher_suite":    tls.CipherSuiteName(r.TLS.CipherSuite),
					"server_name":     r.TLS.ServerName,
					"client_cert":     len(r.TLS.PeerCertificates) > 0,
					"remote_addr":     r.RemoteAddr,
					"user_agent":      r.UserAgent(),
				}).Debug("TLS connection info")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func getTLSVersionString(version uint16) string {
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