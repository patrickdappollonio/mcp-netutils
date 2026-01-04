# Network and domain utils MCP server `mcp-netutils`

[![Github Downloads](https://img.shields.io/github/downloads/patrickdappollonio/mcp-netutils/total?color=orange&label=github%20downloads)](https://github.com/patrickdappollonio/mcp-netutils/releases)

> [!IMPORTANT]
>
> This project is now called `mcp-netutils`. If you're upgrading, please update your references:
> - **Docker images**: `ghcr.io/patrickdappollonio/mcp-netutils:latest`
> - **Homebrew**: `patrickdappollonio/tap/mcp-netutils`
> - **Configuration key**: Use `"netutils"` in your MCP server configuration
>
> For more details about this change, see [issue #52](https://github.com/patrickdappollonio/mcp-domaintools/issues/52).

<img src="https://i.imgur.com/cai3zrG.png" width="160" align="right" /> `mcp-netutils` is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction) server providing comprehensive network and domain analysis capabilities for AI assistants. It enables AI models to perform DNS lookups, WHOIS queries, connectivity testing, TLS certificate analysis, HTTP endpoint monitoring, and hostname resolution.

For local DNS queries, it uses the system's configured DNS servers. For remote DNS queries, it uses Cloudflare DNS-over-HTTPS queries with a fallback to Google DNS-over-HTTPS. This is more than enough for most use cases.

For custom DNS-over-HTTPS servers, you can use the `--remote-server-address` flag. The server endpoint must implement the HTTP response format as defined by [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484#section-4.2).

For custom WHOIS servers, you can use the `--custom-whois-server` flag. The server endpoint must implement the HTTP response format as defined by [RFC 3912](https://datatracker.ietf.org/doc/html/rfc3912), although plain text responses are also supported.

## Features

- **Local DNS Queries**: Perform DNS lookups using the OS-configured DNS servers
- **Remote DNS-over-HTTPS**: Perform secure DNS queries via Cloudflare and Google DNS-over-HTTPS services
- **WHOIS Lookups**: Perform WHOIS queries to get domain registration information
- **Hostname Resolution**: Convert hostnames to their corresponding IP addresses (IPv4, IPv6, or both)
- **Ping Operations**: Test connectivity and measure response times to hosts using ICMP
- **HTTP Ping Operations**: Test HTTP endpoints and measure detailed response times including DNS, connection, TLS, and TTFB timing
- **TLS Certificate Analysis**: Check TLS certificate chains for validity, expiration, and detailed certificate information
- **Multiple Record Types**: Support for A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, and TXT record types
- **Fallback Mechanism**: Automatically tries multiple DNS servers for reliable results
- **SSE Support**: Run as an HTTP server with Server-Sent Events (SSE) for web-based integrations

## Installation

There are two ways to get this MCP server: you can use the Docker mode (which, if you have Docker installed, will automatically download and run the MCP server) or the binary options, both by getting one [from the releases page](https://github.com/patrickdappollonio/mcp-netutils/releases) or by [installing it with Homebrew for macOS and Linux](#homebrew-macos-and-linux).

### Editor Configuration

Add the following configuration to your editor's settings to use `mcp-netutils` via the binary option:

```json5
{
  "mcpServers": {
    "netutils": {
      "command": "mcp-netutils",
      "args": [
        // Uncomment and modify as needed:
        // "--remote-server-address=https://your-custom-doh-server.com/dns-query",
        // "--custom-whois-server=whois.yourdomain.com",
        // "--timeout=5s",
        // "--ping-timeout=5s",
        // "--ping-count=4",
        // "--http-ping-timeout=10s",
        // "--http-ping-count=1",
        // "--tls-timeout=10s"
      ],
      "env": {}
    }
  }
}
```

You can use `mcp-netutils` directly from your `$PATH` as shown above, or provide the full path to the binary (e.g., `/path/to/mcp-netutils`).

Alternatively, you can run `mcp-netutils` directly with Docker without installing the binary:

```json5
{
  "mcpServers": {
    "netutils": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "ghcr.io/patrickdappollonio/mcp-netutils:latest",
        // Add custom options if needed:
        // "--remote-server-address=https://your-custom-doh-server.com/dns-query",
        // "--custom-whois-server=whois.yourdomain.com",
        // "--timeout=5s",
        // "--ping-timeout=5s",
        // "--ping-count=4",
        // "--http-ping-timeout=10s",
        // "--http-ping-count=1",
        // "--tls-timeout=10s"
      ],
      "env": {}
    }
  }
}
```

See ["Available MCP Tools"](#available-mcp-tools) for information on the tools exposed by `mcp-netutils`.

### Homebrew (macOS and Linux)

```bash
brew install patrickdappollonio/tap/mcp-netutils
```

### Docker

The MCP server is available as a Docker image using `stdio` to communicate:

```bash
docker pull ghcr.io/patrickdappollonio/mcp-netutils:latest
docker run --rm ghcr.io/patrickdappollonio/mcp-netutils:latest
```

For SSE mode with Docker, expose the SSE port (default `3000`):

```bash
docker run --rm -p 3000:3000 ghcr.io/patrickdappollonio/mcp-netutils:latest --sse --sse-port 3000
```

Check the implementation above on how to configure the MCP server to run as a container in your editor or tool.

### GitHub Releases

Download the pre-built binaries for your platform from the [GitHub Releases page](https://github.com/patrickdappollonio/mcp-netutils/releases).

## Available MCP Tools

There are **7 tools** available:

- **`local_dns_query`**: Perform DNS queries against the local DNS resolver as configured by the OS
- **`remote_dns_query`**: Perform DNS queries against a remote DNS-over-HTTPS server (Cloudflare/Google)
- **`whois_query`**: Perform WHOIS lookups to get domain registration information
- **`resolve_hostname`**: Convert a hostname to its corresponding IP addresses (IPv4, IPv6, or both)
- **`ping`**: Perform ICMP ping operations to test connectivity and measure response times to hosts
- **`http_ping`**: Perform HTTP ping operations to test HTTP endpoints and measure detailed response times
- **`tls_certificate_check`**: Check TLS certificate chain for a domain to analyze certificate validity, expiration, and chain structure

## Running Modes

### Standard (stdio) Mode

By default, `mcp-netutils` runs in stdio mode, which is suitable for integration with editors and other tools that communicate via standard input/output.

```bash
mcp-netutils
```

### Server-Sent Events (SSE) Mode

Alternatively, you can run `mcp-netutils` as an HTTP server with SSE support for web-based integrations:

```bash
mcp-netutils --sse --sse-port=3000
```

In SSE mode, the server will listen on the specified port (default: 3000) and provide the same MCP tools over HTTP using Server-Sent Events. This is useful for web applications or environments where stdio communication isn't practical.

## Configuration Options

The following command-line flags are available to configure the MCP server:

### General Options
- `--timeout=DURATION`: Timeout for DNS queries (default: 5s)
- `--remote-server-address=URL`: Custom DNS-over-HTTPS server address
- `--custom-whois-server=ADDRESS`: Custom WHOIS server address

### Ping Options
- `--ping-timeout=DURATION`: Timeout for ping operations (default: 5s)
- `--ping-count=NUMBER`: Default number of ping packets to send (default: 4)

### HTTP Ping Options
- `--http-ping-timeout=DURATION`: Timeout for HTTP ping operations (default: 10s)
- `--http-ping-count=NUMBER`: Default number of HTTP ping requests to send (default: 1)

### TLS Options
- `--tls-timeout=DURATION`: Timeout for TLS certificate checks (default: 10s)

### SSE Server Options
- `--sse`: Enable SSE server mode
- `--sse-port=PORT`: Specify the port to listen on (default: 3000)

## Tool Usage Documentation

### Local DNS Query

Performs DNS queries using local OS-defined DNS servers.

**Arguments:**
- `domain` (required): The domain name to query (e.g., `example.com`)
- `record_type` (required): Type of DNS record to query - defaults to `A`
  - Supported types: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `SOA`, `SRV`, `TXT`

**Example:**
```bash
# Query A record for example.com
{"domain": "example.com", "record_type": "A"}

# Query MX records for a domain
{"domain": "example.com", "record_type": "MX"}
```

### Remote DNS Query

Performs DNS queries using remote DNS-over-HTTPS servers (Cloudflare as primary, Google as fallback).

**Arguments:**
- `domain` (required): The domain name to query (e.g., `example.com`)
- `record_type` (required): Type of DNS record to query - defaults to `A`
  - Supported types: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `SOA`, `SRV`, `TXT`

**Example:**
```bash
# Query A record using remote DNS-over-HTTPS
{"domain": "example.com", "record_type": "A"}
```

### WHOIS Query

Performs WHOIS lookups to get domain registration information.

**Arguments:**
- `domain` (required): The domain name to query (e.g., `example.com`)

**Example:**
```bash
# Get WHOIS information for a domain
{"domain": "example.com"}
```

### Hostname Resolution

Converts a hostname to its corresponding IP addresses using the system resolver.

**Arguments:**
- `hostname` (required): The hostname to resolve (e.g., `example.com`)
- `ip_version` (optional): IP version to resolve - defaults to `ipv4`
  - Options: `ipv4`, `ipv6`, `both`

**Example:**
```bash
# Resolve to IPv4 addresses only
{"hostname": "example.com", "ip_version": "ipv4"}

# Resolve to both IPv4 and IPv6
{"hostname": "example.com", "ip_version": "both"}
```

### Ping

Performs ICMP ping operations to test connectivity and measure response times to hosts.

**Arguments:**
- `target` (required): The hostname or IP address to ping (e.g., `example.com` or `8.8.8.8`)
- `count` (optional): Number of ping packets to send - defaults to `4`

**Example:**
```bash
# Ping a host 4 times (default)
{"target": "example.com"}

# Ping a host 10 times
{"target": "8.8.8.8", "count": 10}
```

### HTTP Ping

Performs HTTP ping operations to test HTTP endpoints and measure detailed response times.

**Arguments:**
- `url` (required): The URL to ping (e.g., `https://api.example.com/users`)
- `method` (optional): HTTP method to use - defaults to `GET`
  - Supported methods: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`
- `count` (optional): Number of HTTP requests to send - defaults to `1`

**Response Format:**
The tool returns detailed timing information in a one-liner format:
```
GET https://api.example.com/users 200 OK | dns=42ms conn=156ms tls=298ms ttfb=567ms total=623ms
```

**Timing Measurements:**
- `dns`: DNS resolution time
- `conn`: TCP connection establishment time
- `tls`: TLS handshake time (only for HTTPS URLs)
- `ttfb`: Time to first byte (server response time)
- `total`: Total request time

**Example:**
```bash
# Single GET request
{"url": "https://httpbin.org/get"}

# Multiple POST requests
{"url": "https://httpbin.org/post", "method": "POST", "count": 3}

# Test API endpoint
{"url": "https://api.github.com/users/octocat"}
```

### TLS Certificate Check

Checks TLS certificate chain for a domain to analyze certificate validity, expiration, and chain structure.

**Arguments:**
- `domain` (required): The domain name to check TLS certificate for (e.g., `example.com`)
- `port` (optional): Port to connect to for TLS check - defaults to `443`
- `include_chain` (optional): Whether to include the full certificate chain in the response - defaults to `true`
- `check_expiry` (optional): Whether to check certificate expiration and provide warnings - defaults to `true`
- `server_name` (optional): Server name for SNI (Server Name Indication) - defaults to the domain name

**Example:**
```bash
# Check TLS certificate for domain
{"domain": "example.com"}

# Check TLS certificate on custom port
{"domain": "example.com", "port": 8443}

# Check without certificate chain details
{"domain": "example.com", "include_chain": false}
```

## Examples

### Basic Usage Examples

```bash
# Start the MCP server in stdio mode
mcp-netutils

# Start with custom DNS timeout
mcp-netutils --timeout=10s

# Start with custom HTTP ping settings
mcp-netutils --http-ping-timeout=15s --http-ping-count=3

# Start in SSE mode on port 8080
mcp-netutils --sse --sse-port=8080
```

### Advanced Configuration Examples

```bash
# Use custom DNS-over-HTTPS server
mcp-netutils --remote-server-address=https://dns.quad9.net/dns-query

# Use custom WHOIS server
mcp-netutils --custom-whois-server=whois.custom.com

# Combine multiple options
mcp-netutils \
  --timeout=10s \
  --ping-timeout=3s \
  --ping-count=3 \
  --http-ping-timeout=15s \
  --http-ping-count=2 \
  --tls-timeout=30s
```
