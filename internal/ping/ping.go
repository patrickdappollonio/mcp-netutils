package ping

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Config holds ping configuration.
type Config struct {
	Timeout time.Duration
	Count   int
}

// pingParams represents the parameters for ping operations.
type pingParams struct {
	Target string `json:"target"`
	Count  *int   `json:"count"`
}

// PingResult represents the result of a single ping.
type PingResult struct {
	Sequence     int     `json:"sequence"`
	ResponseTime float64 `json:"response_time_ms"`
	TTL          int     `json:"ttl,omitempty"`
	Success      bool    `json:"success"`
	Error        string  `json:"error,omitempty"`
}

// PingResponse represents the complete ping response.
type PingResponse struct {
	Target          string       `json:"target"`
	ResolvedIP      string       `json:"resolved_ip"`
	PacketsSent     int          `json:"packets_sent"`
	PacketsReceived int          `json:"packets_received"`
	PacketLoss      float64      `json:"packet_loss_percent"`
	Results         []PingResult `json:"results"`
	MinRTT          float64      `json:"min_rtt_ms"`
	MaxRTT          float64      `json:"max_rtt_ms"`
	AvgRTT          float64      `json:"avg_rtt_ms"`
	Timestamp       string       `json:"timestamp"`
}

// rttStats holds statistics for round-trip time calculations.
type rttStats struct {
	totalRTT     time.Duration
	minRTT       time.Duration
	maxRTT       time.Duration
	successCount int
}

// HandlePing performs ping operations to test connectivity to a host.
func HandlePing(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params pingParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	// Validate required parameters
	if params.Target == "" {
		return nil, fmt.Errorf("parameter \"target\" is required")
	}

	// Set default count if not provided
	count := config.Count
	if params.Count != nil && *params.Count > 0 {
		count = *params.Count
	}

	// Create context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	// Resolve the target to an IP address
	resolvedIP, err := net.DefaultResolver.LookupHost(ctxWithTimeout, params.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target %s: %w", params.Target, err)
	}

	if len(resolvedIP) == 0 {
		return nil, fmt.Errorf("no IP addresses found for target %s", params.Target)
	}

	// Use the first resolved IP
	ip := resolvedIP[0]
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Perform ping
	pingResponse, err := performPing(ctxWithTimeout, params.Target, parsedIP, count, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("ping failed: %w", err)
	}

	// Use the response package to handle JSON encoding and MCP tool result creation
	return resp.JSON(pingResponse)
}

// createPingResponse initializes a new PingResponse struct.
func createPingResponse(target string, ip net.IP, count int) *PingResponse {
	return &PingResponse{
		Target:      target,
		ResolvedIP:  ip.String(),
		PacketsSent: count,
		Results:     make([]PingResult, 0, count),
		Timestamp:   time.Now().Format(time.RFC3339),
	}
}

// updateRTTStats updates the RTT statistics with a new successful ping result.
func updateRTTStats(stats *rttStats, duration time.Duration) {
	stats.totalRTT += duration
	if stats.successCount == 0 || duration < stats.minRTT {
		stats.minRTT = duration
	}
	if stats.successCount == 0 || duration > stats.maxRTT {
		stats.maxRTT = duration
	}
	stats.successCount++
}

// calculateFinalStats calculates and sets the final statistics on the response.
func calculateFinalStats(response *PingResponse, stats *rttStats) {
	response.PacketsReceived = stats.successCount
	response.PacketLoss = float64(response.PacketsSent-stats.successCount) / float64(response.PacketsSent) * 100

	if stats.successCount > 0 {
		response.MinRTT = float64(stats.minRTT) / float64(time.Millisecond)
		response.MaxRTT = float64(stats.maxRTT) / float64(time.Millisecond)
		response.AvgRTT = float64(stats.totalRTT) / float64(stats.successCount) / float64(time.Millisecond)
	}
}

// waitBetweenPings waits for the appropriate interval between pings.
func waitBetweenPings(i, count int) {
	if i < count-1 {
		time.Sleep(time.Second)
	}
}

// performPing executes the actual ping operation.
func performPing(ctx context.Context, target string, ip net.IP, count int, timeout time.Duration) (*PingResponse, error) {
	response := createPingResponse(target, ip, count)
	var stats rttStats

	// Determine IP version
	isIPv4 := ip.To4() != nil

	// Create ICMP connection
	network := "ip4:icmp"
	if !isIPv4 {
		network = "ip6:ipv6-icmp"
	}

	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		// If we can't create a raw socket, fall back to a simpler approach
		return performSimplePing(ctx, target, ip, count, timeout)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			// Log error but don't fail the operation
			fmt.Printf("Warning: failed to close connection: %v\n", closeErr)
		}
	}()

	// Set timeout for the connection
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

pingLoop:
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			break pingLoop
		default:
		}

		result := PingResult{
			Sequence: i + 1,
		}

		// Create ICMP message
		var message *icmp.Message
		if isIPv4 {
			message = &icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   1234,
					Seq:  i + 1,
					Data: []byte("mcp-netutils ping"),
				},
			}
		} else {
			message = &icmp.Message{
				Type: ipv6.ICMPTypeEchoRequest,
				Code: 0,
				Body: &icmp.Echo{
					ID:   1234,
					Seq:  i + 1,
					Data: []byte("mcp-netutils ping"),
				},
			}
		}

		// Marshal the message
		messageBytes, err := message.Marshal(nil)
		if err != nil {
			result.Error = err.Error()
			response.Results = append(response.Results, result)
			continue
		}

		// Send the packet
		start := time.Now()
		_, err = conn.WriteTo(messageBytes, &net.IPAddr{IP: ip})
		if err != nil {
			result.Error = err.Error()
			response.Results = append(response.Results, result)
			continue
		}

		// Read the reply
		reply := make([]byte, 1500)
		if err := conn.SetReadDeadline(time.Now().Add(time.Second * 5)); err != nil {
			result.Error = fmt.Sprintf("failed to set read deadline: %v", err)
			response.Results = append(response.Results, result)
			continue
		}
		n, _, err := conn.ReadFrom(reply)
		if err != nil {
			result.Error = err.Error()
			response.Results = append(response.Results, result)
			continue
		}

		duration := time.Since(start)
		result.ResponseTime = float64(duration) / float64(time.Millisecond)
		result.Success = true

		// Parse the reply to get TTL (if available)
		if isIPv4 {
			// For IPv4, we need to parse the IP header to get the TTL
			if n >= 20 { // Minimum IPv4 header size
				// TTL is at offset 8 in the IPv4 header
				result.TTL = int(reply[8])
			}
		} else {
			// For IPv6, we need to parse the IPv6 header to get the Hop Limit
			if n >= 40 { // Minimum IPv6 header size
				// Hop Limit is at offset 7 in the IPv6 header
				result.TTL = int(reply[7])
			}
		}

		// Update statistics
		updateRTTStats(&stats, duration)
		response.Results = append(response.Results, result)

		// Wait before next ping
		waitBetweenPings(i, count)
	}

	// Calculate final statistics
	calculateFinalStats(response, &stats)

	return response, nil
}

// performSimplePing performs a simple connectivity test using TCP connection when ICMP is not available.
func performSimplePing(ctx context.Context, target string, ip net.IP, count int, timeout time.Duration) (*PingResponse, error) {
	response := createPingResponse(target, ip, count)
	var stats rttStats

	// Use common ports for connectivity testing
	ports := []string{"80", "443", "22", "25", "53"}

connectLoop:
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			break connectLoop
		default:
		}

		result := PingResult{
			Sequence: i + 1,
		}

		// Try to connect to one of the common ports
		var connected bool
		var duration time.Duration

		for _, port := range ports {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), timeout/time.Duration(len(ports)))
			duration = time.Since(start)

			if err == nil {
				if closeErr := conn.Close(); closeErr != nil {
					// Log error but continue with the operation
					fmt.Printf("Warning: failed to close TCP connection: %v\n", closeErr)
				}
				connected = true
				break
			}
		}

		if connected {
			result.Success = true
			result.ResponseTime = float64(duration) / float64(time.Millisecond)

			// Update statistics
			updateRTTStats(&stats, duration)
		} else {
			result.Error = "connection failed to all tested ports"
		}

		response.Results = append(response.Results, result)

		// Wait before next ping
		waitBetweenPings(i, count)
	}

	// Calculate final statistics
	calculateFinalStats(response, &stats)

	return response, nil
}
