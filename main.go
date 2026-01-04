package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/patrickdappollonio/mcp-netutils/internal/dns"
	"github.com/patrickdappollonio/mcp-netutils/internal/http_ping"
	"github.com/patrickdappollonio/mcp-netutils/internal/ping"
	internalServer "github.com/patrickdappollonio/mcp-netutils/internal/server"
	"github.com/patrickdappollonio/mcp-netutils/internal/tls"
	"github.com/patrickdappollonio/mcp-netutils/internal/whois"
	"golang.org/x/sync/errgroup"
)

var (
	remoteServerAddress string
	customWhoisServer   string
	enableSSEServer     bool
	sseServerPort       int
	timeout             time.Duration
	pingTimeout         time.Duration
	pingCount           int
	httpPingTimeout     time.Duration
	httpPingCount       int
	tlsTimeout          time.Duration
	version             = "dev"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err.Error())
		os.Exit(1)
	}
}

func run() error {
	flag.StringVar(&remoteServerAddress, "remote-server-address", "", "Custom DNS-over-HTTPS server address")
	flag.StringVar(&customWhoisServer, "custom-whois-server", "", "Custom WHOIS server address")
	flag.BoolVar(&enableSSEServer, "sse", false, "Enable SSE server mode")
	flag.IntVar(&sseServerPort, "sse-port", 3000, "SSE server port (if SSE server mode is enabled)")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "Timeout for DNS queries")
	flag.DurationVar(&pingTimeout, "ping-timeout", 5*time.Second, "Timeout for ping operations")
	flag.IntVar(&pingCount, "ping-count", 4, "Default number of ping packets to send")
	flag.DurationVar(&httpPingTimeout, "http-ping-timeout", 10*time.Second, "Timeout for HTTP ping operations")
	flag.IntVar(&httpPingCount, "http-ping-count", 1, "Default number of HTTP ping requests to send")
	flag.DurationVar(&tlsTimeout, "tls-timeout", 10*time.Second, "Timeout for TLS certificate checks")

	flag.Parse()

	// Create DNS query configuration
	queryConfig := &dns.QueryConfig{
		Timeout:             timeout,
		RemoteServerAddress: remoteServerAddress,
	}

	// Create WHOIS configuration
	whoisConfig := &whois.Config{
		CustomServer: customWhoisServer,
	}

	// Create ping configuration
	pingConfig := &ping.Config{
		Timeout: pingTimeout,
		Count:   pingCount,
	}

	// Create HTTP ping configuration
	httpPingConfig := &http_ping.Config{
		Timeout: httpPingTimeout,
		Count:   httpPingCount,
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Timeout: tlsTimeout,
		Port:    443,
	}

	// Setup network utility tools
	s, err := internalServer.SetupTools(&internalServer.NetUtilsConfig{
		QueryConfig:    queryConfig,
		WhoisConfig:    whoisConfig,
		PingConfig:     pingConfig,
		HTTPPingConfig: httpPingConfig,
		TLSConfig:      tlsConfig,
		Version:        version,
	})
	if err != nil {
		return fmt.Errorf("error setting up network utility tools: %w", err)
	}

	// Start the server
	if enableSSEServer {
		sse := server.NewSSEServer(s)

		eg := errgroup.Group{}
		eg.Go(func() error {
			addr := fmt.Sprintf(":%d", sseServerPort)
			log.Printf("Starting SSE server on %s...\n", addr)
			if err := sse.Start(addr); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("error starting SSE server: %w", err)
			}
			return nil
		})

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		eg.Go(func() error {
			<-ctx.Done()
			log.Println("Shutting down SSE server...")

			cancelCtx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelFunc()

			if err := sse.Shutdown(cancelCtx); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("error shutting down SSE server: %w", err)
			}

			log.Println("SSE server shut down successfully, bye!")
			return nil
		})

		if err := eg.Wait(); err != nil {
			return err
		}
	} else {
		if err := server.ServeStdio(s); err != nil {
			return fmt.Errorf("error starting stdio server: %w", err)
		}
	}

	return nil
}
