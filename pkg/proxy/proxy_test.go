package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/arulrajnet/basic-auth-proxy/pkg/session"
)

func TestProxyTrustedIPs(t *testing.T) {
	// 1. Mock Backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	tests := []struct {
		name           string
		trustedIPs     []string
		clientIP       string
		xffIncoming    string
		realIPIncoming string
		protoIncoming  string
		portIncoming   string
		shouldTrust    bool
	}{
		{
			name:           "Untrusted (Default): Should overwrite X-Real-IP and sanitize XFF/Proto/Port",
			trustedIPs:     []string{},
			clientIP:       "1.2.3.4:12345",
			xffIncoming:    "100.100.100.100",
			realIPIncoming: "100.100.100.100",
			protoIncoming:  "https",
			portIncoming:   "443",
			shouldTrust:    false,
		},
		{
			name:           "Trusted IP: Should preserve headers",
			trustedIPs:     []string{"1.2.3.4/32"},
			clientIP:       "1.2.3.4:12345",
			xffIncoming:    "100.100.100.100",
			realIPIncoming: "100.100.100.100",
			protoIncoming:  "https",
			portIncoming:   "443",
			shouldTrust:    true,
		},
		{
			name:           "Trusted CIDR: Should preserve headers",
			trustedIPs:     []string{"1.2.3.0/24"},
			clientIP:       "1.2.3.4:5678",
			xffIncoming:    "100.100.100.100",
			realIPIncoming: "100.100.100.100",
			protoIncoming:  "https",
			portIncoming:   "443",
			shouldTrust:    true,
		},
		{
			name:           "Untrusted IP in CIDR range mismatch",
			trustedIPs:     []string{"10.0.0.0/8"},
			clientIP:       "1.2.3.4:12345",
			xffIncoming:    "100.100.100.100",
			realIPIncoming: "100.100.100.100",
			protoIncoming:  "https",
			portIncoming:   "443",
			shouldTrust:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Config
			cfg := &Config{
				Proxy: ProxyConfig{
					TrustedIPs:  tt.trustedIPs,
					ProxyPrefix: "/",
				},
				Upstreams: []Upstream{{URL: backendURL}},
				Cookie: CookieConfig{
					Name: "test_cookie",
				},
			}

			// Session Mock
			sm := session.NewSessionManager("12345678901234567890123456789012", "12345678901234567890123456789012") // 32 bytes

			// Create Proxy
			// Need to initialize session manager first
			sm.ConfigureCookie("test_cookie", "/", "", 3600, false, true, "lax")

			p := NewProxy(cfg, sm)

			// Setup request
			req := httptest.NewRequest("GET", "http://proxy/", nil)
			req.RemoteAddr = tt.clientIP
			req.Header.Set("X-Forwarded-For", tt.xffIncoming)
			req.Header.Set("X-Real-IP", tt.realIPIncoming)
			req.Header.Set("X-Forwarded-Proto", tt.protoIncoming)
			req.Header.Set("X-Forwarded-Port", tt.portIncoming)

			// Check if reverseProxy is initialized
			if p.reverseProxy == nil {
				t.Fatal("ReverseProxy is nil")
			}

			// Invoke Director directly
			p.reverseProxy.Director(req)

			// Check Headers
			gotXFF := req.Header.Get("X-Forwarded-For")
			gotRealIP := req.Header.Get("X-Real-IP")
			gotProto := req.Header.Get("X-Forwarded-Proto")
			gotPort := req.Header.Get("X-Forwarded-Port")

			// Verification
			if tt.shouldTrust {
				// Trusted: preserved
				if gotXFF != tt.xffIncoming {
					t.Errorf("Trusted: expected XFF %q, got %q", tt.xffIncoming, gotXFF)
				}
				if gotRealIP != tt.realIPIncoming {
					t.Errorf("Trusted: expected RealIP %q, got %q", tt.realIPIncoming, gotRealIP)
				}
				if gotProto != tt.protoIncoming {
					t.Errorf("Trusted: expected Proto %q, got %q", tt.protoIncoming, gotProto)
				}
				if gotPort != tt.portIncoming {
					t.Errorf("Trusted: expected Port %q, got %q", tt.portIncoming, gotPort)
				}
			} else {
				// Untrusted: sanitized
				if gotXFF != "" {
					t.Errorf("Untrusted: expected empty XFF (deleted), got %q", gotXFF)
				}

				// Expected Real IP should be Client IP without port
				clientIPNoPort := tt.clientIP
				if host, _, err := net.SplitHostPort(tt.clientIP); err == nil {
					clientIPNoPort = host
				}

				if gotRealIP != clientIPNoPort {
					t.Errorf("Untrusted: expected RealIP %q, got %q", clientIPNoPort, gotRealIP)
				}
				if gotProto != "" {
					t.Errorf("Untrusted: expected empty Proto, got %q", gotProto)
				}
				if gotPort != "" {
					t.Errorf("Untrusted: expected empty Port, got %q", gotPort)
				}
			}
		})
	}
}
