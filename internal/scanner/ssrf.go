package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// blockedIP reports whether an IP address must not be dialed by the scanner.
//
// The domain-health scanner issues outbound HTTP/HTTPS requests to
// user-controlled hostnames. Without a guard, a user could point a subdomain's
// A/AAAA record at an internal address (e.g. the 169.254.169.254 cloud
// metadata endpoint, 127.0.0.1, 10.x/172.16.x/192.168.x, fc00::/7 ...) and have
// the server probe its own network — a classic SSRF. This rejects loopback,
// private, link-local, multicast and other reserved ranges.
func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0: // 0.0.0.0/8
			return true
		case v4[0] == 169 && v4[1] == 254: // link-local, incl. 169.254.169.254
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // CGNAT 100.64.0.0/10
			return true
		}
	} else if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc { // fc00::/7 ULA
		return true
	}
	return false
}

// guardedDialContext returns a DialContext that refuses to connect to
// loopback/private/link-local/reserved addresses. When fixedIP is non-empty it
// connects to that IP (keeping the requested port) after validating it;
// otherwise it resolves the requested host and dials the first permitted
// address. Host/SNI are preserved by the caller.
func guardedDialContext(fixedIP string, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		host := fixedIP
		if host == "" {
			host, _, err = net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
		}

		var candidates []net.IP
		if ip := net.ParseIP(host); ip != nil {
			candidates = []net.IP{ip}
		} else {
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			candidates = ips
		}

		d := net.Dialer{Timeout: timeout}
		var lastErr error
		for _, ip := range candidates {
			if blockedIP(ip) {
				lastErr = fmt.Errorf("refusing to connect to blocked address %s", ip)
				continue
			}
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no permitted address for %s", host)
		}
		return nil, lastErr
	}
}

// dialTLSGuarded opens a TLS connection to domain:443 (or to dialIP when set),
// after ensuring the destination is not a blocked address. SNI stays domain.
func dialTLSGuarded(domain, dialIP string) (*tls.Conn, error) {
	host := dialIP
	if host == "" {
		ips, err := net.LookupIP(domain)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if !blockedIP(ip) {
				host = ip.String()
				break
			}
		}
		if host == "" {
			return nil, fmt.Errorf("refusing to connect: %s resolves only to blocked addresses", domain)
		}
	} else if ip := net.ParseIP(host); ip == nil || blockedIP(ip) {
		return nil, fmt.Errorf("refusing to connect to blocked address %s", host)
	}

	return tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		net.JoinHostPort(host, "443"),
		&tls.Config{InsecureSkipVerify: true, ServerName: domain},
	)
}
