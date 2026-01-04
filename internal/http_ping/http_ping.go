package http_ping

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
)

// Config holds HTTP ping configuration.
type Config struct {
	Timeout time.Duration
	Count   int
}

// httpPingParams represents the parameters for HTTP ping operations.
type httpPingParams struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Count  *int   `json:"count"`
}

// HTTPPingResult represents the result of a single HTTP ping.
type HTTPPingResult struct {
	Sequence   int           `json:"sequence"`
	Method     string        `json:"method"`
	URL        string        `json:"url"`
	StatusCode int           `json:"status_code"`
	Status     string        `json:"status"`
	DNSTime    time.Duration `json:"dns_time_ms"`
	ConnTime   time.Duration `json:"connect_time_ms"`
	TLSTime    time.Duration `json:"tls_time_ms"`
	TTFBTime   time.Duration `json:"ttfb_time_ms"`
	TotalTime  time.Duration `json:"total_time_ms"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
	OneLiner   string        `json:"one_liner"`
}

// HTTPPingResponse represents the complete HTTP ping response.
type HTTPPingResponse struct {
	Target       string           `json:"target"`
	Method       string           `json:"method"`
	RequestsSent int              `json:"requests_sent"`
	SuccessCount int              `json:"success_count"`
	FailureCount int              `json:"failure_count"`
	Results      []HTTPPingResult `json:"results"`
	AvgDNSTime   time.Duration    `json:"avg_dns_time_ms"`
	AvgConnTime  time.Duration    `json:"avg_connect_time_ms"`
	AvgTLSTime   time.Duration    `json:"avg_tls_time_ms"`
	AvgTTFBTime  time.Duration    `json:"avg_ttfb_time_ms"`
	AvgTotalTime time.Duration    `json:"avg_total_time_ms"`
	Timestamp    string           `json:"timestamp"`
}

// timingStats holds timing statistics for calculations.
type timingStats struct {
	totalDNS   time.Duration
	totalConn  time.Duration
	totalTLS   time.Duration
	totalTTFB  time.Duration
	totalTotal time.Duration
	count      int
}

// HandleHTTPPing performs HTTP ping operations to test connectivity to a HTTP endpoint.
func HandleHTTPPing(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params httpPingParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	// Validate required parameters
	if params.URL == "" {
		return nil, fmt.Errorf("parameter \"url\" is required")
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(params.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Ensure we have a scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	// Validate scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme: %s", parsedURL.Scheme)
	}

	// Set default method if not provided
	method := strings.ToUpper(params.Method)
	if method == "" {
		method = "GET"
	}

	// Validate method
	if method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" && method != "HEAD" && method != "OPTIONS" && method != "PATCH" {
		return nil, fmt.Errorf("unsupported HTTP method: %s", method)
	}

	// Set default count if not provided
	count := config.Count
	if params.Count != nil && *params.Count > 0 {
		count = *params.Count
	}

	// Create context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	// Perform HTTP ping
	httpResponse, err := performHTTPPing(ctxWithTimeout, method, parsedURL, count, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("HTTP ping failed: %w", err)
	}

	// Use the response package to handle JSON encoding and MCP tool result creation
	return resp.JSON(httpResponse)
}

// performHTTPPing executes the actual HTTP ping operation.
func performHTTPPing(ctx context.Context, method string, parsedURL *url.URL, count int, timeout time.Duration) (*HTTPPingResponse, error) {
	// Create clean URL without query parameters for display
	cleanURL := &url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   parsedURL.Path,
	}

	response := &HTTPPingResponse{
		Target:       cleanURL.String(),
		Method:       method,
		RequestsSent: count,
		Results:      make([]HTTPPingResult, 0, count),
		Timestamp:    time.Now().Format(time.RFC3339),
	}

	var stats timingStats

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return response, nil
		default:
		}

		result := performSingleHTTPPing(ctx, method, parsedURL, i+1, timeout)
		response.Results = append(response.Results, result)

		if result.Success {
			response.SuccessCount++
			updateTimingStats(&stats, result)
		} else {
			response.FailureCount++
		}

		// Wait between requests (except for the last one)
		if i < count-1 {
			time.Sleep(time.Second)
		}
	}

	// Calculate averages
	calculateAverages(response, &stats)

	return response, nil
}

// performSingleHTTPPing performs a single HTTP ping request.
func performSingleHTTPPing(ctx context.Context, method string, parsedURL *url.URL, sequence int, timeout time.Duration) HTTPPingResult {
	// Create clean URL without query parameters for display
	cleanURL := &url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   parsedURL.Path,
	}

	result := HTTPPingResult{
		Sequence: sequence,
		Method:   method,
		URL:      cleanURL.String(),
	}

	// Timing variables
	var dnsStart, dnsEnd time.Time
	var connStart, connEnd time.Time
	var tlsStart, tlsEnd time.Time
	var reqStart, respStart time.Time

	// Create HTTP trace
	trace := &httptrace.ClientTrace{
		DNSStart: func(dnsInfo httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
		},
		ConnectStart: func(network, addr string) {
			connStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connEnd = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsEnd = time.Now()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			reqStart = time.Now()
		},
		GotFirstResponseByte: func() {
			respStart = time.Now()
		},
	}

	// Create HTTP client with trace
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true, // Ensure fresh connections for accurate timing
		},
	}

	// Create request
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, parsedURL.String(), nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		result.OneLiner = fmt.Sprintf("%s %s ERROR | %s", method, cleanURL.String(), result.Error)
		return result
	}

	// Set User-Agent
	req.Header.Set("User-Agent", "mcp-netutils/http_ping")

	// Record start time
	startTime := time.Now()

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		totalTime := time.Since(startTime)
		result.TotalTime = totalTime
		result.Error = fmt.Sprintf("request failed: %v", err)
		result.OneLiner = fmt.Sprintf("%s %s ERROR | total=%dms | %s", method, cleanURL.String(), totalTime.Milliseconds(), result.Error)
		return result
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Record end time
	endTime := time.Now()

	// Calculate timings
	result.TotalTime = endTime.Sub(startTime)
	result.StatusCode = resp.StatusCode
	result.Status = resp.Status
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400

	// Calculate individual timings
	if !dnsEnd.IsZero() && !dnsStart.IsZero() {
		result.DNSTime = dnsEnd.Sub(dnsStart)
	}
	if !connEnd.IsZero() && !connStart.IsZero() {
		result.ConnTime = connEnd.Sub(connStart)
	}
	if !tlsEnd.IsZero() && !tlsStart.IsZero() {
		result.TLSTime = tlsEnd.Sub(tlsStart)
	}
	if !respStart.IsZero() && !reqStart.IsZero() {
		result.TTFBTime = respStart.Sub(reqStart)
	}

	// Create one-liner format
	var tlsInfo string
	if parsedURL.Scheme == "https" {
		tlsInfo = fmt.Sprintf("tls=%dms ", result.TLSTime.Milliseconds())
	}

	result.OneLiner = fmt.Sprintf("%s %s %d %s | dns=%dms conn=%dms %sttfb=%dms total=%dms",
		method, cleanURL.String(), result.StatusCode, getStatusText(result.StatusCode),
		result.DNSTime.Milliseconds(), result.ConnTime.Milliseconds(),
		tlsInfo, result.TTFBTime.Milliseconds(), result.TotalTime.Milliseconds())

	return result
}

// updateTimingStats updates the timing statistics with a successful result.
func updateTimingStats(stats *timingStats, result HTTPPingResult) {
	stats.totalDNS += result.DNSTime
	stats.totalConn += result.ConnTime
	stats.totalTLS += result.TLSTime
	stats.totalTTFB += result.TTFBTime
	stats.totalTotal += result.TotalTime
	stats.count++
}

// calculateAverages calculates and sets the average timing statistics.
func calculateAverages(response *HTTPPingResponse, stats *timingStats) {
	if stats.count > 0 {
		response.AvgDNSTime = stats.totalDNS / time.Duration(stats.count)
		response.AvgConnTime = stats.totalConn / time.Duration(stats.count)
		response.AvgTLSTime = stats.totalTLS / time.Duration(stats.count)
		response.AvgTTFBTime = stats.totalTTFB / time.Duration(stats.count)
		response.AvgTotalTime = stats.totalTotal / time.Duration(stats.count)
	}
}

// getStatusText returns a human-readable status text for common HTTP status codes.
func getStatusText(statusCode int) string {
	switch statusCode {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return http.StatusText(statusCode)
	}
}
