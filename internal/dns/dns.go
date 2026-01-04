package dns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/miekg/dns"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
	doh "github.com/shynome/doh-client"
)

// QueryConfig holds DNS query configuration.
type QueryConfig struct {
	Timeout             time.Duration
	RemoteServerAddress string
}

// dnsQueryParams represents the parameters for DNS queries.
type dnsQueryParams struct {
	Domain     string `json:"domain"`
	RecordType string `json:"record_type"`
}

// HandleLocalDNSQuery processes local DNS queries using OS-defined DNS servers.
func HandleLocalDNSQuery(ctx context.Context, request mcp.CallToolRequest, config *QueryConfig) (*mcp.CallToolResult, error) {
	var params dnsQueryParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	// Validate required parameters
	if params.Domain == "" {
		return nil, fmt.Errorf("parameter \"domain\" is required")
	}

	if params.RecordType == "" {
		return nil, fmt.Errorf("parameter \"record_type\" is required")
	}

	// Validate domain format
	if strings.Contains(params.Domain, "..") || strings.HasPrefix(params.Domain, ".") {
		return nil, fmt.Errorf("invalid domain format: %q", params.Domain)
	}

	recordType, err := ConvertToQType(params.RecordType)
	if err != nil {
		return nil, err
	}

	// Ensure domain ends with a dot for DNS queries
	domain := params.Domain
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	// Create a new DNS message
	m := new(dns.Msg)
	m.SetQuestion(domain, recordType)
	m.RecursionDesired = true

	// Use local resolver for query
	c := new(dns.Client)
	c.Timeout = config.Timeout

	var dnsResponse *dns.Msg
	var queryErr error

	// Get DNS servers in a cross-platform way
	servers, err := getSystemDNSServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS servers: %w", err)
	}

	// Try each configured server until we get a response
	for _, server := range servers {
		serverAddr := server
		if !strings.Contains(server, ":") {
			serverAddr = net.JoinHostPort(server, "53")
		}
		dnsResponse, _, queryErr = c.Exchange(m, serverAddr)
		if queryErr == nil && dnsResponse != nil {
			break
		}
	}

	if queryErr != nil {
		return nil, fmt.Errorf("DNS query failed: %w", queryErr)
	}

	if dnsResponse == nil {
		return nil, fmt.Errorf("no response from DNS servers")
	}

	// Format the response as JSON using the response package
	result := createDNSResponse(dnsResponse)
	return resp.JSON(result)
}

// getSystemDNSServers returns a list of system DNS servers in a cross-platform way
func getSystemDNSServers(ctx context.Context) ([]string, error) {
	// Use Go's pure DNS resolver implementation with a custom dialer
	// to capture the DNS server addresses used by the system - works on all platforms

	// We'll capture any DNS servers discovered during Dial
	discoveredServers := make([]string, 0)

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	// Create a custom resolver that will capture which servers it's using
	netResolver := &net.Resolver{
		PreferGo: true, // Use the pure Go resolver
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Extract the server IP from the address (e.g., "8.8.8.8:53")
			host, _, err := net.SplitHostPort(address)
			if err == nil && host != "" && host != "127.0.0.1" && host != "::1" {
				// Prevent duplicates
				found := slices.Contains(discoveredServers, host)
				if !found {
					discoveredServers = append(discoveredServers, host)
				}
			}

			// Use the standard dialer to actually make the connection
			return dialer.DialContext(ctx, network, address)
		},
	}

	// Use the resolver to make a real DNS query, which will call our custom Dial function
	// The actual results don't matter - we just need to trigger the Dial function
	// to capture DNS server addresses
	_, _ = netResolver.LookupHost(ctx, "one.one.one.one") // Cloudflare's DNS that's likely to exist

	// If we found any DNS servers through our custom dialer, return them
	if len(discoveredServers) > 0 {
		return discoveredServers, nil
	}

	// As a secondary fallback, try to read from /etc/resolv.conf
	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(dnsConfig.Servers) > 0 {
		return dnsConfig.Servers, nil
	}

	// If no DNS servers were found, return an error
	return nil, fmt.Errorf("could not discover any system DNS servers")
}

// HandleRemoteDNSQuery processes DNS queries using DNS-over-HTTPS.
func HandleRemoteDNSQuery(ctx context.Context, request mcp.CallToolRequest, config *QueryConfig) (*mcp.CallToolResult, error) {
	var params dnsQueryParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	// Validate required parameters
	if params.Domain == "" {
		return nil, fmt.Errorf("domain parameter is required")
	}

	if params.RecordType == "" {
		return nil, fmt.Errorf("record_type parameter is required")
	}

	// Validate domain format
	if strings.Contains(params.Domain, "..") || strings.HasPrefix(params.Domain, ".") {
		return nil, fmt.Errorf("invalid domain format: %s", params.Domain)
	}

	recordType, err := ConvertToQType(params.RecordType)
	if err != nil {
		return nil, err
	}

	// Ensure domain ends with a dot for DNS queries
	domain := params.Domain
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	// Create a new DNS message
	m := new(dns.Msg)
	m.SetQuestion(domain, recordType)
	m.RecursionDesired = true

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	// Set timeout context
	ctxWithTimeout, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	// Use the specified DoH server or default to Cloudflare
	dohServer := "https://cloudflare-dns.com/dns-query"
	if config.RemoteServerAddress != "" {
		dohServer = config.RemoteServerAddress
	}

	// Create DoH connection
	conn := doh.NewConn(httpClient, ctxWithTimeout, dohServer)

	// Set up DNS connection using the DoH client
	dnsConn := &dns.Conn{Conn: conn}

	// Send the query
	err = dnsConn.WriteMsg(m)
	if err != nil {
		// Try Google as fallback if not using custom server
		if config.RemoteServerAddress == "" {
			conn = doh.NewConn(httpClient, ctxWithTimeout, "https://dns.google/dns-query")
			dnsConn = &dns.Conn{Conn: conn}
			err = dnsConn.WriteMsg(m)
			if err != nil {
				return nil, fmt.Errorf("DNS-over-HTTPS query failed: %v", err)
			}
		} else {
			return nil, fmt.Errorf("DNS-over-HTTPS query failed: %v", err)
		}
	}

	// Read the response
	dnsResponse, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %v", err)
	}

	// Format the response as JSON using the response package
	result := createDNSResponse(dnsResponse)
	return resp.JSON(result)
}

// ConvertToQType converts a string record type to the corresponding DNS query type.
// This function supports all DNS record types available in the miekg/dns package.
func ConvertToQType(recordType string) (uint16, error) {
	if qtype, exists := dns.StringToType[recordType]; exists {
		return qtype, nil
	}
	return 0, fmt.Errorf("unsupported record type %q", recordType)
}

// createDNSResponse creates a JSON-serializable map from a DNS message.
func createDNSResponse(response *dns.Msg) map[string]any {
	// Create a response structure that matches DNS public JSON spec
	result := map[string]any{
		"status":            response.Rcode,
		"truncated":         response.Truncated,
		"authenticatedData": response.AuthenticatedData,
		"checkingDisabled":  response.CheckingDisabled,
	}

	// Add the question section
	questions := []map[string]interface{}{}
	for _, q := range response.Question {
		question := map[string]interface{}{
			"name": q.Name,
			"type": q.Qtype,
		}

		// Add human-readable record type name
		if typeName, ok := dns.TypeToString[q.Qtype]; ok {
			question["typeName"] = typeName
		}

		questions = append(questions, question)
	}
	result["question"] = questions

	// Add the answer section
	answers := []map[string]any{}
	for _, a := range response.Answer {
		// Extract the data based on record type
		var data string
		switch a.Header().Rrtype {
		case dns.TypeA:
			if rec, ok := a.(*dns.A); ok {
				data = rec.A.String()
			}
		case dns.TypeAAAA:
			if rec, ok := a.(*dns.AAAA); ok {
				data = rec.AAAA.String()
			}
		case dns.TypeCAA:
			if rec, ok := a.(*dns.CAA); ok {
				data = fmt.Sprintf("%d %s %q", rec.Flag, rec.Tag, rec.Value)
			}
		case dns.TypeCNAME:
			if rec, ok := a.(*dns.CNAME); ok {
				data = rec.Target
			}
		case dns.TypeMX:
			if rec, ok := a.(*dns.MX); ok {
				data = fmt.Sprintf("%d %s", rec.Preference, rec.Mx)
			}
		case dns.TypeNS:
			if rec, ok := a.(*dns.NS); ok {
				data = rec.Ns
			}
		case dns.TypePTR:
			if rec, ok := a.(*dns.PTR); ok {
				data = rec.Ptr
			}
		case dns.TypeSOA:
			if rec, ok := a.(*dns.SOA); ok {
				data = fmt.Sprintf("%s %s %d %d %d %d %d",
					rec.Ns, rec.Mbox, rec.Serial, rec.Refresh, rec.Retry, rec.Expire, rec.Minttl)
			}
		case dns.TypeSRV:
			if rec, ok := a.(*dns.SRV); ok {
				data = fmt.Sprintf("%d %d %d %s", rec.Priority, rec.Weight, rec.Port, rec.Target)
			}
		case dns.TypeTXT:
			if rec, ok := a.(*dns.TXT); ok {
				data = strings.Join(rec.Txt, " ")
			}
		default:
			// Fall back to the string representation
			data = strings.Fields(a.String())[4]
		}

		answer := map[string]interface{}{
			"name": a.Header().Name,
			"type": a.Header().Rrtype,
			"TTL":  a.Header().Ttl,
			"data": data,
		}

		// Add human-readable record type name
		if typeName, ok := dns.TypeToString[a.Header().Rrtype]; ok {
			answer["typeName"] = typeName
		}

		answers = append(answers, answer)
	}

	if len(answers) > 0 {
		result["answer"] = answers
	}

	// Add human-readable DNS status code
	if response.Rcode >= 0 && response.Rcode < len(dns.RcodeToString) {
		result["statusMessage"] = dns.RcodeToString[response.Rcode]
	}

	// Check for EDNS client subnet
	for _, extra := range response.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, o := range opt.Option {
				if subnet, ok := o.(*dns.EDNS0_SUBNET); ok {
					mask := subnet.SourceNetmask
					result["ednsClientSubnet"] = fmt.Sprintf("%s/%d", subnet.Address.String(), mask)
					break
				}
			}
		}
	}

	return result
}
