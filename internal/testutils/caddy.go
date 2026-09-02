package testutils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

// Harness runs an in-process Caddy instance for end-to-end tests.
//
// Caddy keeps its configuration in process-global state, so only one Harness
// can be active at a time and tests using it must not call t.Parallel.
type Harness struct {
	// AdminAddr is the address Caddy's admin API listens on.
	AdminAddr string
	// HTTPAddr is the address the test HTTP server listens on.
	HTTPAddr string
	// L4Addr is the address available for a layer4 server to listen on.
	L4Addr string

	client *http.Client
}

// NewHarness allocates addresses for an in-process Caddy instance and ensures
// it is stopped when t finishes. It does not load a configuration; call
// [Harness.Load] with one.
func NewHarness(t *testing.T) *Harness {
	t.Helper()

	h := &Harness{
		AdminAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		HTTPAddr:  fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		L4Addr:    fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Logf("failed stopping caddy: %s", err)
		}
	})

	return h
}

// Load applies the configuration to the running Caddy instance and waits for
// the HTTP address to accept connections.
//
// forceReload is always set, so loading an unchanged configuration still
// exercises the full reload path rather than being skipped as a no-op.
func (h *Harness) Load(t *testing.T, config string) {
	t.Helper()

	require.NoError(t, caddy.Load([]byte(config), true))
	h.waitForListener(t, h.HTTPAddr)
}

// Reload is [Harness.Load]. It exists to make the intent of a test obvious at
// the call site.
func (h *Harness) Reload(t *testing.T, config string) {
	t.Helper()

	h.Load(t, config)
}

// ReloadWithin applies the configuration and fails if it does not complete
// within timeout.
//
// A reload that hangs rather than fails is the signature of the streaming
// bouncer blocking on an unguarded channel send: Caddy calls Cleanup on the
// outgoing app, which waits in Core.Shutdown's wg.Wait() for a producer whose
// consumer has already returned. Without this watchdog that shows up as the
// whole test binary timing out, with no indication of which call hung.
func (h *Harness) ReloadWithin(t *testing.T, config string, timeout time.Duration) {
	t.Helper()

	errCh := make(chan error, 1)
	go func() { errCh <- caddy.Load([]byte(config), true) }()

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(timeout):
		require.FailNowf(t, "reload timed out",
			"caddy.Load did not return within %s; the decision stream is likely blocking Core.Shutdown", timeout)
	}

	h.waitForListener(t, h.HTTPAddr)
}

// LoadExpectingError applies the configuration and requires that it fails,
// returning the error so tests can assert on it. The previously loaded
// configuration keeps running.
func (h *Harness) LoadExpectingError(t *testing.T, config string) error {
	t.Helper()

	err := caddy.Load([]byte(config), true)
	require.Error(t, err, "expected configuration to be rejected")

	return err
}

// Get performs a GET against the test HTTP server, presenting clientIP as the
// client address via X-Forwarded-For. Pass an empty clientIP to omit the header.
func (h *Harness) Get(t *testing.T, path, clientIP string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(path), http.NoBody)
	require.NoError(t, err)

	return h.Do(t, req, clientIP)
}

// Post performs a POST with the given body and content type.
func (h *Harness) Post(t *testing.T, path, contentType string, body io.Reader, clientIP string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.url(path), body)
	require.NoError(t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return h.Do(t, req, clientIP)
}

// Do performs the request, presenting clientIP via X-Forwarded-For, and returns
// the response along with its fully read body.
func (h *Harness) Do(t *testing.T, req *http.Request, clientIP string) (*http.Response, string) {
	t.Helper()

	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	resp, err := h.client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp, string(body)
}

// AdminPost performs a POST against Caddy's admin API and returns the status
// code and body.
func (h *Harness) AdminPost(t *testing.T, path string, body io.Reader) (int, string) {
	t.Helper()

	return h.adminRequest(t, http.MethodPost, path, body)
}

// AdminGet performs a GET against Caddy's admin API and returns the status code
// and body.
func (h *Harness) AdminGet(t *testing.T, path string) (int, string) {
	t.Helper()

	return h.adminRequest(t, http.MethodGet, path, http.NoBody)
}

func (h *Harness) adminRequest(t *testing.T, method, path string, body io.Reader) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+h.AdminAddr+path, body)
	require.NoError(t, err)

	resp, err := h.client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(b)
}

func (h *Harness) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return "http://" + h.HTTPAddr + path
}

// waitForListener blocks until addr accepts a TCP connection.
func (h *Harness) waitForListener(t *testing.T, addr string) {
	t.Helper()

	WaitFor(t, 10*time.Second, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()

		return true
	}, "caddy did not start listening on %s", addr)
}

// WaitFor polls condition until it reports true or the timeout elapses, failing
// the test with the given message if it never does.
//
// Use this instead of a fixed sleep when waiting on the streaming bouncer: the
// ticker interval only bounds when the poll starts, not when the decision has
// been applied to the store.
//
// Prefer it over require.Eventually for any condition that touches a container.
// Eventually runs the condition in a fresh goroutine per tick, so a slow call
// (a docker exec easily outlasts the tick interval) can still be in flight when
// the test finishes; it then calls t.Fatal or t.Log on a completed test and
// panics or reports a spurious failure. This loop is synchronous, so the
// condition can never outlive the test.
func WaitFor(t *testing.T, timeout time.Duration, condition func() bool, msg string, args ...any) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	require.FailNowf(t, "timed out waiting for condition", msg, args...)
}

// WaitForStatus polls the given path until it responds with the expected status
// code. It is the usual way to wait for a decision to reach the bouncer via the
// streaming bouncer's ticker.
//
// Connection errors are treated as "not yet": a reload briefly tears the
// listener down, and failing on that would make every reload test racy.
func (h *Harness) WaitForStatus(t *testing.T, path, clientIP string, expected int, timeout time.Duration) {
	t.Helper()

	var last string
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		code, err := h.try(t, path, clientIP)
		switch {
		case err != nil:
			last = err.Error()
		case code == expected:
			return
		default:
			last = fmt.Sprintf("status %d", code)
		}

		time.Sleep(100 * time.Millisecond)
	}

	require.FailNowf(t, "timed out waiting for status",
		"expected status %d for client %s at %s; last result: %s", expected, clientIP, path, last)
}

// try performs a GET without failing the test, for use in polling loops.
func (h *Harness) try(t *testing.T, path, clientIP string) (int, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(path), http.NoBody)
	if err != nil {
		return 0, err
	}
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

var testIPCounter atomic.Uint32

// NextTestIP returns an IP address unique within this test binary, in the
// 10.77.0.0/16 range.
//
// Tests share a CrowdSec container, so each one bans its own address to stay
// independent of the others. The address reaches the bouncer via
// X-Forwarded-For, which requires the server to trust 127.0.0.1 as a proxy.
func NextTestIP(t *testing.T) string {
	t.Helper()

	n := testIPCounter.Add(1)

	return fmt.Sprintf("10.77.%d.%d", (n/254)%254, (n%254)+1)
}

// Ban adds a ban decision for ip.
func Ban(t *testing.T, c *Container, ip string, duration time.Duration) {
	t.Helper()

	BanTyped(t, c, ip, "ban", duration)
}

// BanTyped adds a decision of the given type (ban, captcha, throttle) for ip.
func BanTyped(t *testing.T, c *Container, ip, typ string, duration time.Duration) {
	t.Helper()

	cscli(t, c, "decisions", "add", "--ip", ip, "--type", typ, "--duration", duration.String())
}

// UnBan removes all decisions for ip.
func UnBan(t *testing.T, c *Container, ip string) {
	t.Helper()

	cscli(t, c, "decisions", "delete", "--ip", ip)
}

// HasDecisionFor reports whether the LAPI currently holds a decision for ip.
//
// Use it to distinguish "the bouncer did not block" from "the decision had not
// been created yet", which would otherwise make a passing assertion meaningless.
func HasDecisionFor(t *testing.T, c *Container, ip string) bool {
	t.Helper()

	ctx, cancel := containerContext()
	defer cancel()

	code, output, err := c.ExecCombined(ctx, []string{"cscli", "decisions", "list", "--ip", ip, "-o", "json"})
	require.NoError(t, err)
	require.Equalf(t, 0, code, "cscli decisions list failed: %s", output)

	// cscli prints "null" rather than an empty array when nothing matches
	if output == "" || output == "null" {
		return false
	}

	var decisions []any
	if err := json.Unmarshal([]byte(output), &decisions); err != nil {
		t.Logf("could not parse cscli output %q: %s", output, err)
		return false
	}

	return len(decisions) > 0
}

func cscli(t *testing.T, c *Container, args ...string) {
	t.Helper()

	ctx, cancel := containerContext()
	defer cancel()

	code, reader, err := c.Exec(ctx, append([]string{"cscli"}, args...))
	require.NoError(t, err)

	output := readAll(reader)
	require.Equalf(t, 0, code, "cscli %s failed: %s", strings.Join(args, " "), output)

	if output != "" {
		t.Logf("cscli %s: %s", strings.Join(args, " "), output)
	}
}

// containerContext returns the context used for commands run inside a
// container.
//
// It deliberately does not derive from t.Context(): that context is cancelled
// just before t.Cleanup functions run, so a cleanup that removes a decision
// would always fail with "context canceled".
func containerContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func readAll(reader io.Reader) string {
	if reader == nil {
		return ""
	}

	b, err := io.ReadAll(reader)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(b))
}

// FreeAddr returns a loopback address that nothing was listening on at the time
// of the call. Useful for pointing a component at an endpoint that is certain to
// be unreachable.
func FreeAddr(t *testing.T) string {
	t.Helper()

	return fmt.Sprintf("127.0.0.1:%d", freePort(t))
}

// freePort returns a TCP port that was free at the time of the call.
func freePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	return l.Addr().(*net.TCPAddr).Port
}
