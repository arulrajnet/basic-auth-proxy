package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/arulrajnet/basic-auth-proxy/pkg/session"
)

func TestProxyTrustUpstream(t *testing.T) {
	// 1. Mock Backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Forwarded-For", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Received-Real-IP", r.Header.Get("X-Real-IP"))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	tests := []struct {
		name           string
		trustUpstream  bool
		clientIP       string
		xffIncoming    string
		realIPIncoming string
		protoIncoming  string
		portIncoming   string
		expectRealIP   string
		expectProto    string
		expectPort     string
	}{
		{
			name:           "Untrusted (Default): Should overwrite X-Real-IP and sanitize XFF/Proto/Port",
			trustUpstream:  false,
			clientIP:       "1.2.3.4:12345",
			xffIncoming:    "100.100.100.100",
			realIPIncoming: "100.100.100.100",
			protoIncoming:  "https",
			portIncoming:   "443",
			expectRealIP:   "1.2.3.4:12345", // overwritten to RemoteAddr
			expectProto:    "",              // Deleted
			expectPort:     "",              // Deleted
		},
		{
			name:           "Trusted: Should preserve XFF and X-Real-IP and Proto/Port",
			trustUpstream:  true,
			clientIP:       "1.2.3.4:12345",
			xffIncoming:    "100.100.100.100",
			realIPIncoming: "100.100.100.100",
			protoIncoming:  "https",
			portIncoming:   "443",
			expectRealIP:   "100.100.100.100",
			expectProto:    "https",
			expectPort:     "443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Config
			cfg := &Config{
				Proxy: ProxyConfig{
					TrustUpstream: tt.trustUpstream,
					ProxyPrefix:   "/",
				},
				Upstreams: []Upstream{{URL: backendURL}},
				Cookie: CookieConfig{
					Name: "test_cookie",
				},
			}

			// Session Mock
			sm := session.NewSessionManager("12345678901234567890123456789012", "12345678901234567890123456789012") // 32 bytes

			// Create Proxy
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
			if tt.trustUpstream {
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
				if gotRealIP != tt.clientIP {
					t.Errorf("Untrusted: expected RealIP %q, got %q", tt.clientIP, gotRealIP)
				}
				if gotProto != tt.expectProto {
					t.Errorf("Untrusted: expected Proto %q, got %q", tt.expectProto, gotProto)
				}
				if gotPort != tt.expectPort {
					t.Errorf("Untrusted: expected Port %q, got %q", tt.expectPort, gotPort)
				}
			}
		})
	}
}
