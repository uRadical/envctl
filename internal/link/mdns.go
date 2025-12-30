package link

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/grandcat/zeroconf"
)

const (
	linkServiceType = "_envctl-link._tcp"
	linkDomain      = "local."
)

// LinkAdvertisement represents an mDNS advertisement
type LinkAdvertisement struct {
	server *zeroconf.Server
}

// AdvertiseLinkSession advertises the linking session via mDNS
func AdvertiseLinkSession(code string) (*LinkAdvertisement, error) {
	// Service name includes code prefix for discovery
	// Target needs to know the code anyway to connect
	serviceName := fmt.Sprintf("envctl-link-%s", code[:3])

	server, err := zeroconf.Register(
		serviceName,
		linkServiceType,
		linkDomain,
		LinkPort,
		[]string{"v=1", "code=" + code[:3]}, // Only prefix for discovery
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("registering mDNS: %w", err)
	}

	slog.Debug("mDNS advertisement started", "service", serviceName)

	return &LinkAdvertisement{server: server}, nil
}

// Stop stops the mDNS advertisement
func (a *LinkAdvertisement) Stop() {
	if a != nil && a.server != nil {
		a.server.Shutdown()
		slog.Debug("mDNS advertisement stopped")
	}
}

// DiscoverLinkSession finds a linking session with the given code via mDNS
func DiscoverLinkSession(code string) (string, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return "", fmt.Errorf("creating resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		err := resolver.Browse(ctx, linkServiceType, linkDomain, entries)
		if err != nil {
			slog.Debug("mDNS browse error", "err", err)
		}
	}()

	codePrefix := code[:3]

	for entry := range entries {
		// Check if this is the right session
		for _, txt := range entry.Text {
			if txt == "code="+codePrefix {
				// Found it
				if len(entry.AddrIPv4) > 0 {
					addr := fmt.Sprintf("%s:%d", entry.AddrIPv4[0], entry.Port)
					slog.Debug("found link session via mDNS", "addr", addr)
					return addr, nil
				}
				if len(entry.AddrIPv6) > 0 {
					addr := fmt.Sprintf("[%s]:%d", entry.AddrIPv6[0], entry.Port)
					slog.Debug("found link session via mDNS", "addr", addr)
					return addr, nil
				}
			}
		}
	}

	return "", fmt.Errorf("link session not found via mDNS")
}

// FindLinkSessionOnNetwork scans the local network for link sessions
func FindLinkSessionOnNetwork() (string, error) {
	// Browse for any envctl-link services without code filter
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return "", fmt.Errorf("creating resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	go func() {
		err := resolver.Browse(ctx, linkServiceType, linkDomain, entries)
		if err != nil {
			slog.Debug("mDNS browse error", "err", err)
		}
	}()

	for entry := range entries {
		if len(entry.AddrIPv4) > 0 {
			addr := fmt.Sprintf("%s:%d", entry.AddrIPv4[0], entry.Port)
			slog.Debug("found link session on network", "addr", addr)
			return addr, nil
		}
		if len(entry.AddrIPv6) > 0 {
			addr := fmt.Sprintf("[%s]:%d", entry.AddrIPv6[0], entry.Port)
			slog.Debug("found link session on network", "addr", addr)
			return addr, nil
		}
	}

	return "", fmt.Errorf("no link sessions found on network")
}
