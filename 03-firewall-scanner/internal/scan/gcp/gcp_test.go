package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/proto"
)

type fakeLister struct {
	fws []*computepb.Firewall
	err error
}

func (f fakeLister) ListFirewalls(context.Context, string) ([]*computepb.Firewall, error) {
	return f.fws, f.err
}

func fw(name, dir string, disabled bool, ranges []string, allowed ...*computepb.Allowed) *computepb.Firewall {
	return &computepb.Firewall{
		Name:         proto.String(name),
		Network:      proto.String("https://www.googleapis.com/compute/v1/projects/p/global/networks/default"),
		Direction:    proto.String(dir),
		Disabled:     proto.Bool(disabled),
		SourceRanges: ranges,
		Allowed:      allowed,
	}
}

func allow(p string, ports ...string) *computepb.Allowed {
	return &computepb.Allowed{IPProtocol: proto.String(p), Ports: ports}
}

func TestScan(t *testing.T) {
	open := []string{"0.0.0.0/0"}
	s := &Scanner{Projects: []string{"p"}, Lister: fakeLister{fws: []*computepb.Firewall{
		fw("z-open-ssh", "INGRESS", false, open, allow("tcp", "22")),
		fw("a-allow-all", "INGRESS", false, open, allow("icmp")),
		fw("disabled", "INGRESS", true, open, allow("tcp", "22")),
		fw("egress", "EGRESS", false, open, allow("tcp", "22")),
		fw("internal", "INGRESS", false, []string{"10.0.0.0/8"}, allow("all")),
		{Name: proto.String("deny"), Direction: proto.String("INGRESS"), SourceRanges: open,
			Denied: []*computepb.Denied{{IPProtocol: proto.String("tcp")}}},
	}}}
	got, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "a-allow-all" || got[1].Name != "z-open-ssh" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Network != "default" || got[0].Project != "p" {
		t.Fatalf("network/project: %+v", got[0])
	}
	if r := got[0].InsecureRules[0]; r.Protocol != "icmp" || r.Port != "all" || r.Source != "0.0.0.0/0" {
		t.Fatalf("rule: %+v", r)
	}
}

func TestScanError(t *testing.T) {
	boom := errors.New("403 forbidden")
	s := &Scanner{Projects: []string{"p"}, Lister: fakeLister{err: boom}}
	if _, err := s.Scan(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewRequiresProject(t *testing.T) {
	if _, _, err := New(context.Background(), Options{}); err == nil {
		t.Fatal("want error for empty project")
	}
}

// TestClientListerPagination runs the real SDK client against a local HTTP
// server, so page tokens are followed by the SDK iterator. No network, no credentials.
func TestClientListerPagination(t *testing.T) {
	var tokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("pageToken")
		tokens = append(tokens, tok)
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		switch tok {
		case "":
			body = map[string]any{"items": []map[string]any{{"name": "one", "direction": "INGRESS",
				"sourceRanges": []string{"0.0.0.0/0"}, "allowed": []map[string]any{{"IPProtocol": "tcp", "ports": []string{"22"}}}}},
				"nextPageToken": "t2"}
		case "t2":
			body = map[string]any{"items": []map[string]any{{"name": "two", "direction": "INGRESS",
				"sourceRanges": []string{"0.0.0.0/0"}, "allowed": []map[string]any{{"IPProtocol": "udp"}}}}}
		default:
			http.Error(w, `{"error":{"code":400,"message":"bad token"}}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	c, err := compute.NewFirewallsRESTClient(context.Background(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s := &Scanner{Projects: []string{"p"}, Lister: ClientLister{Client: c}}
	got, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "one" || got[1].Name != "two" {
		t.Fatalf("got %+v", got)
	}
	if len(tokens) != 2 || tokens[1] != "t2" {
		t.Fatalf("page tokens seen: %v", tokens)
	}
}

func TestClientListerHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"code":403,"message":"forbidden"}}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c, err := compute.NewFirewallsRESTClient(context.Background(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s := &Scanner{Projects: []string{"p"}, Lister: ClientLister{Client: c}}
	if _, err := s.Scan(context.Background()); err == nil {
		t.Fatal("want error")
	}
}

// A failure after some rules were listed keeps those rules and returns the error.
func TestScanKeepsPartialResults(t *testing.T) {
	boom := errors.New("page 2 failed")
	open := []string{"0.0.0.0/0"}
	s := &Scanner{Projects: []string{"p"}, Lister: fakeLister{err: boom, fws: []*computepb.Firewall{
		fw("one", "INGRESS", false, open, allow("tcp", "22")),
	}}}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0].Name != "one" {
		t.Fatalf("got %+v", got)
	}
}

// The SDK ignores the context for in-flight HTTP calls, so ClientLister must
// stop waiting itself when the context expires.
func TestClientListerTimesOutOnSlowServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	defer close(release)
	c, err := compute.NewFirewallsRESTClient(context.Background(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	// The client is not closed: the abandoned call still uses it.
	var abandoned atomic.Bool
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	s := &Scanner{Projects: []string{"p"}, Lister: ClientLister{Client: c, Abandoned: &abandoned}}
	if _, err := s.Scan(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("returned after %v", d)
	}
	if !abandoned.Load() {
		t.Fatal("Abandoned was not set")
	}
}

// The context given to Scan reaches the SDK call: a cancelled context fails the list.
func TestClientListerHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, err := compute.NewFirewallsRESTClient(context.Background(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &Scanner{Projects: []string{"p"}, Lister: ClientLister{Client: c}}
	if _, err := s.Scan(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}
