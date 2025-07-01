package proxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// RequestLogger returns a middleware that logs HTTP requests
func RequestLogger(logger zerolog.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture the status code
			responseWriter := NewResponseWriter(w)

			// Call the next handler
			next.ServeHTTP(responseWriter, r)

			// Calculate duration
			duration := time.Since(start)

			// Log the request
			logger.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("query", r.URL.RawQuery).
				Str("remote_addr", r.RemoteAddr).
				Str("user_agent", r.UserAgent()).
				Int("status", responseWriter.StatusCode).
				Dur("duration", duration).
				Str("size", formatSize(responseWriter.Size)).
				Msg("HTTP Request")
		})
	}
}

// ResponseWriter is a wrapper for http.ResponseWriter that captures status code and size
type ResponseWriter struct {
	http.ResponseWriter
	StatusCode int
	Size       int
}

// NewResponseWriter creates a new ResponseWriter
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		StatusCode:     http.StatusOK, // Default status code
	}
}

// WriteHeader captures the status code
func (rw *ResponseWriter) WriteHeader(statusCode int) {
	rw.StatusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

// Write captures the response size
func (rw *ResponseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.Size += size
	return size, err
}

// formatSize formats the size in bytes to a human-readable string
func formatSize(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.2f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
}
