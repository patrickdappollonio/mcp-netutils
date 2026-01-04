package whois

import (
	"context"
	"fmt"
	"strings"

	"github.com/likexian/whois"
	"github.com/mark3labs/mcp-go/mcp"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
)

// Config holds WHOIS configuration.
type Config struct {
	CustomServer string
}

// whoisQueryParams represents the parameters for WHOIS queries.
type whoisQueryParams struct {
	Domain string `json:"domain"`
}

// HandleWhoisQuery processes WHOIS queries.
func HandleWhoisQuery(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params whoisQueryParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	// Validate required parameters
	if params.Domain == "" {
		return nil, fmt.Errorf("parameter \"domain\" is required")
	}

	// Clean and validate domain format
	domain := strings.TrimSpace(params.Domain)
	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") {
		return nil, fmt.Errorf("invalid domain format: %q", domain)
	}

	var result string
	var err error

	// Use custom server if provided, otherwise use default
	if config.CustomServer != "" {
		result, err = whois.Whois(domain, config.CustomServer)
	} else {
		result, err = whois.Whois(domain)
	}

	if err != nil {
		return nil, fmt.Errorf("WHOIS query failed: %w", err)
	}

	// Format response as JSON using the response package
	responseData := map[string]interface{}{
		"domain": domain,
		"result": result,
	}

	return resp.JSON(responseData)
}
