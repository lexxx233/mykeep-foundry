package host

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// errForbiddenHost / errBlockedIP / errBadURL are the fixed, detail-free errors a tool
// sees — never the internal reason, so a tool can't probe the network by error message.
var (
	errBadURL        = errors.New("bad_url")
	errForbiddenHost = errors.New("host_not_granted")
	errBlockedIP     = errors.New("blocked_address")
)

// Broker is Foundry's egress proxy for tool HTTP. It enforces the tool's host allowlist
// and a resolve-then-pin SSRF guard: the hostname is resolved once, every resolved IP is
// checked against the private/loopback/link-local denylist, and the connection is pinned
// to that vetted IP so DNS can't be rebound to an internal address between check and dial.
type Broker struct {
	maxBytes int64
	timeout  time.Duration
	// allowPrivate is for tests only; tool egress never reaches private space.
	allowPrivate bool
}

// NewBroker builds an egress broker. maxBytes<=0 defaults to 5 MiB.
func NewBroker(maxBytes int64) *Broker {
	if maxBytes <= 0 {
		maxBytes = 5 << 20
	}
	return &Broker{maxBytes: maxBytes, timeout: 30 * time.Second}
}

type fetchReq struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type fetchResp struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated"`
}

// fetch performs a guarded request. allowHosts is the tool's network capability grant
// (exact hostnames); an empty grant means no network.
func (b *Broker) fetch(ctx context.Context, allowHosts []string, fr fetchReq) (*fetchResp, error) {
	u, err := url.Parse(fr.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errBadURL
	}
	host := u.Hostname()
	if !hostAllowed(host, allowHosts) {
		return nil, errForbiddenHost
	}

	// Resolve once, vet every IP, and pin the dial to a vetted address.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errBadURL
	}
	var pinned string
	for _, ip := range ips {
		if b.blocked(ip.IP) {
			return nil, errBlockedIP // any resolved IP in private space → refuse the whole host
		}
		if pinned == "" {
			pinned = ip.IP.String()
		}
	}

	method := strings.ToUpper(fr.Method)
	if method == "" {
		method = "GET"
	}
	var body io.Reader
	if fr.Body != "" {
		body = strings.NewReader(fr.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fr.URL, body)
	if err != nil {
		return nil, errBadURL
	}
	for k, v := range fr.Headers {
		if !hopOrDangerous(k) {
			req.Header.Set(k, v)
		}
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	pinnedAddr := net.JoinHostPort(pinned, port)
	transport := &http.Transport{
		// Pin the connection to the vetted IP regardless of what the address says.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, pinnedAddr)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   b.timeout,
		// Don't auto-follow redirects: a 30x could send us to an internal host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errBadURL
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, b.maxBytes+1)
	data, _ := io.ReadAll(limited)
	truncated := int64(len(data)) > b.maxBytes
	if truncated {
		data = data[:b.maxBytes]
	}
	hdr := map[string]string{}
	for k := range resp.Header {
		hdr[k] = resp.Header.Get(k)
	}
	return &fetchResp{Status: resp.StatusCode, Headers: hdr, Body: string(data), Truncated: truncated}, nil
}

// hostAllowed matches an exact hostname or a leading-dot suffix grant (".example.com").
func hostAllowed(host string, allow []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range allow {
		a = strings.ToLower(a)
		if a == host {
			return true
		}
		if strings.HasPrefix(a, ".") && strings.HasSuffix(host, a) {
			return true
		}
	}
	return false
}

func (b *Broker) blocked(ip net.IP) bool {
	if b.allowPrivate {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		isUniqueLocal(ip)
}

// isUniqueLocal covers IPv6 ULA (fc00::/7), which net.IP.IsPrivate also handles, but we
// keep it explicit for clarity.
func isUniqueLocal(ip net.IP) bool {
	v6 := ip.To16()
	return v6 != nil && ip.To4() == nil && (v6[0]&0xfe) == 0xfc
}

// hopOrDangerous strips hop-by-hop and host-spoofing headers a tool shouldn't set.
func hopOrDangerous(k string) bool {
	switch strings.ToLower(k) {
	case "host", "content-length", "connection", "transfer-encoding", "upgrade":
		return true
	}
	return false
}
