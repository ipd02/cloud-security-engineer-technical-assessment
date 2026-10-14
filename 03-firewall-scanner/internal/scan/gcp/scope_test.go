package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

type fakeNetworkPolicies map[string]struct {
	policies []*computepb.FirewallPolicy
	err      error
}

func (f fakeNetworkPolicies) ListNetworkPolicies(_ context.Context, project string) ([]*computepb.FirewallPolicy, error) {
	r := f[project]
	return r.policies, r.err
}

type fakeHierarchy map[string]struct {
	policies []*computepb.FirewallPolicy
	err      error
}

func (f fakeHierarchy) ListHierarchicalPolicies(_ context.Context, parent string) ([]*computepb.FirewallPolicy, error) {
	r := f[parent]
	return r.policies, r.err
}

type fakeAssets struct {
	byType map[string][]Asset
	errs   map[string]error
	scopes []string
}

func (f *fakeAssets) Search(_ context.Context, scope, assetType string) ([]Asset, error) {
	f.scopes = append(f.scopes, scope)
	return f.byType[assetType], f.errs[assetType]
}

func policyRule(prio int32, action, dir string, src []string, l4 ...*computepb.FirewallPolicyRuleMatcherLayer4Config) *computepb.FirewallPolicyRule {
	return &computepb.FirewallPolicyRule{
		Priority: proto.Int32(prio), Action: proto.String(action), Direction: proto.String(dir),
		Match: &computepb.FirewallPolicyRuleMatcher{SrcIpRanges: src, Layer4Configs: l4},
	}
}

func l4(p string, ports ...string) *computepb.FirewallPolicyRuleMatcherLayer4Config {
	return &computepb.FirewallPolicyRuleMatcherLayer4Config{IpProtocol: proto.String(p), Ports: ports}
}

func policy(name string, targets []string, rules ...*computepb.FirewallPolicyRule) *computepb.FirewallPolicy {
	p := &computepb.FirewallPolicy{Name: proto.String(name), Rules: rules}
	for _, t := range targets {
		p.Associations = append(p.Associations, &computepb.FirewallPolicyAssociation{AttachmentTarget: proto.String(t)})
	}
	return p
}

func firewallAsset(t *testing.T, project, name string, fields map[string]any) Asset {
	t.Helper()
	s, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatal(err)
	}
	return Asset{Name: "//compute.googleapis.com/projects/" + project + "/global/firewalls/" + name, Resource: s}
}

func TestProjectScanReadsNetworkPolicies(t *testing.T) {
	open := []string{"0.0.0.0/0"}
	s := &Scanner{
		Projects: []string{"p"},
		Lister:   fakeLister{},
		NetworkPolicies: fakeNetworkPolicies{"p": {policies: []*computepb.FirewallPolicy{
			policy("open-policy", []string{"https://www.googleapis.com/compute/v1/projects/p/global/networks/vpc-b", "https://www.googleapis.com/compute/v1/projects/p/global/networks/vpc-a"},
				policyRule(1000, "allow", "INGRESS", open, l4("tcp", "22"), l4("udp")),
				policyRule(2000, "deny", "INGRESS", open, l4("all")),
				policyRule(3000, "goto_next", "INGRESS", open, l4("all")),
				policyRule(4000, "allow", "EGRESS", open, l4("all")),
				policyRule(5000, "allow", "INGRESS", []string{"10.0.0.0/8"}, l4("all"))),
			policy("closed-policy", nil, policyRule(1, "allow", "INGRESS", []string{"10.0.0.0/8"}, l4("all"))),
		}}},
	}
	got, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	g := got[0]
	if g.Name != "open-policy" || g.Type != model.TypeNetworkPolicy || g.Project != "p" || g.Network != "vpc-a,vpc-b" {
		t.Fatalf("policy rule: %+v", g)
	}
	if len(g.InsecureRules) != 2 || g.InsecureRules[0].Protocol != "tcp" || g.InsecureRules[0].Port != "22" ||
		g.InsecureRules[0].RuleID != "1000" || g.InsecureRules[1].Protocol != "udp" || g.InsecureRules[1].Port != "all" {
		t.Fatalf("insecure rules: %+v", g.InsecureRules)
	}
}

func TestPolicyErrorKeepsOtherFindings(t *testing.T) {
	boom := errors.New("403 policies")
	open := []string{"0.0.0.0/0"}
	s := &Scanner{
		Projects:        []string{"p"},
		Lister:          fakeLister{fws: []*computepb.Firewall{fw("vpc-open", "INGRESS", false, open, allow("tcp", "22"))}},
		NetworkPolicies: fakeNetworkPolicies{"p": {err: boom}},
	}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "network firewall policies in project p") {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0].Name != "vpc-open" {
		t.Fatalf("got %+v", got)
	}
}

func TestScopeScan(t *testing.T) {
	boom := errors.New("403 on project b")
	assets := &fakeAssets{byType: map[string][]Asset{
		assetFirewall: {
			firewallAsset(t, "proj-a", "open-ssh", map[string]any{
				"direction": "INGRESS", "sourceRanges": []any{"0.0.0.0/0"},
				"network": "https://www.googleapis.com/compute/v1/projects/proj-a/global/networks/default",
				"allowed": []any{map[string]any{"IPProtocol": "tcp", "ports": []any{"22"}}},
			}),
			firewallAsset(t, "proj-b", "disabled", map[string]any{
				"direction": "INGRESS", "disabled": true, "sourceRanges": []any{"0.0.0.0/0"},
				"allowed": []any{map[string]any{"IPProtocol": "all"}},
			}),
			firewallAsset(t, "proj-b", "internal", map[string]any{
				"direction": "INGRESS", "sourceRanges": []any{"10.0.0.0/8"},
				"allowed": []any{map[string]any{"IPProtocol": "all"}},
			}),
			{Name: "//compute.googleapis.com/projects/proj-b/global/firewalls/no-data"},
		},
		assetFolder: {{Name: "//cloudresourcemanager.googleapis.com/folders/222"}, {Name: "//cloudresourcemanager.googleapis.com/folders/111"}},
		assetProject: {
			{Name: "//cloudresourcemanager.googleapis.com/projects/proj-a", DisplayName: "My First Project"},
			{Attributes: mustStruct(t, map[string]any{"projectId": "proj-b"})},
			{Attributes: mustStruct(t, map[string]any{"projectId": "proj-off"}), DisplayName: "Off"},
			{DisplayName: "Only a friendly name"},
		},
	}}
	open := []string{"0.0.0.0/0"}
	s := &Scanner{
		Scopes: []string{"organizations/123"},
		Assets: assets,
		Hierarchy: fakeHierarchy{
			"organizations/123": {policies: []*computepb.FirewallPolicy{policy("org-policy", []string{"organizations/123"}, policyRule(10, "allow", "INGRESS", open, l4("tcp", "443")))}},
			"folders/111":       {policies: []*computepb.FirewallPolicy{policy("folder-policy", []string{"folders/111"}, policyRule(10, "deny", "INGRESS", open, l4("all")))}},
			"folders/222":       {err: boom},
		},
		NetworkPolicies: fakeNetworkPolicies{
			"proj-a":   {policies: []*computepb.FirewallPolicy{policy("net-policy", []string{"default"}, policyRule(5, "allow", "INGRESS", open, l4("all")))}},
			"proj-b":   {err: boom},
			"proj-off": {err: errors.New("googleapi: Error 403: Compute Engine API has not been used in project 1 before or it is disabled. SERVICE_DISABLED")},
		},
	}
	got, err := s.Scan(context.Background())
	if err == nil {
		t.Fatal("want the collected errors")
	}
	for _, want := range []string{"asset //compute.googleapis.com/projects/proj-b/global/firewalls/no-data has no resource data",
		"list hierarchical firewall policies of folders/222", "network firewall policies in project proj-b", "has no project id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "proj-off") {
		t.Errorf("a project with the Compute API off must be skipped: %v", err)
	}
	type key struct{ name, typ, project string }
	var keys []key
	for _, r := range got {
		keys = append(keys, key{r.Name, r.Type, r.Project})
	}
	want := []key{
		{"open-ssh", "", "proj-a"},
		{"net-policy", model.TypeNetworkPolicy, "proj-a"},
		{"org-policy", model.TypeHierarchicalPolicy, ""},
	}
	// Sorted by project, then type, then name: the empty project comes first.
	want = []key{want[2], want[0], want[1]}
	if len(keys) != len(want) {
		t.Fatalf("got %+v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("got %+v; want %+v", keys, want)
		}
	}
	if got[1].Network != "default" || got[1].InsecureRules[0].Port != "22" {
		t.Fatalf("vpc rule from asset: %+v", got[1])
	}
	for _, sc := range assets.scopes {
		if sc != "organizations/123" {
			t.Fatalf("scope = %q", sc)
		}
	}
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScopeSearchErrorKeepsPolicies(t *testing.T) {
	boom := errors.New("403 asset")
	open := []string{"0.0.0.0/0"}
	s := &Scanner{
		Scopes: []string{"folders/9"},
		Assets: &fakeAssets{errs: map[string]error{assetFirewall: boom, assetFolder: boom, assetProject: boom}},
		Hierarchy: fakeHierarchy{"folders/9": {policies: []*computepb.FirewallPolicy{
			policy("p", nil, policyRule(1, "allow", "INGRESS", open, l4("all")))}}},
	}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) || len(got) != 1 || got[0].Name != "p" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestNewValidatesScope(t *testing.T) {
	for _, o := range []Options{{Org: "1", Folder: "2"}} {
		if _, _, err := New(context.Background(), o); err == nil {
			t.Fatalf("want an error for %+v", o)
		}
	}
}

// The Cloud Asset REST client against a local server: scope, asset type,
// read mask, page tokens, and the decoded Firewall data.
func TestAssetClientSearch(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path+"?"+r.URL.Query().Encode())
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("pageToken") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{map[string]any{
				"name": "//compute.googleapis.com/projects/p1/global/firewalls/one", "assetType": assetFirewall,
				"versionedResources": []any{map[string]any{"version": "v1", "resource": map[string]any{
					"direction": "INGRESS", "sourceRanges": []any{"0.0.0.0/0"},
					"allowed": []any{map[string]any{"IPProtocol": "udp", "ports": []any{"53"}}}}}},
			}}, "nextPageToken": "t2"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{map[string]any{
			"name": "//compute.googleapis.com/projects/p2/global/firewalls/two", "assetType": assetFirewall,
		}}})
	}))
	defer srv.Close()

	var abandoned atomic.Bool
	c, err := newAssetClient(context.Background(), &abandoned, option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	assets, err := c.Search(context.Background(), "organizations/123", assetFirewall)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || !strings.HasPrefix(requests[0], "/v1/organizations/123:searchAllResources?") ||
		!strings.Contains(requests[0], "assetTypes=compute.googleapis.com%2FFirewall") ||
		!strings.Contains(requests[0], "versionedResources") || !strings.Contains(requests[1], "pageToken=t2") {
		t.Fatalf("requests: %v", requests)
	}
	if len(assets) != 2 || assets[1].Resource != nil {
		t.Fatalf("assets: %+v", assets)
	}
	fwp, err := firewallFromAsset(assets[0])
	if err != nil {
		t.Fatal(err)
	}
	s := &Scanner{}
	rule, ok := s.vpcRule(fwp, projectFromName(assets[0].Name))
	if !ok || rule.Project != "p1" || rule.InsecureRules[0].Protocol != "udp" || rule.InsecureRules[0].Port != "53" {
		t.Fatalf("rule: %+v ok=%v", rule, ok)
	}
}

func TestNetworkPolicyClientAggregatedList(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": map[string]any{
			"global":              map[string]any{"firewallPolicies": []any{map[string]any{"name": "g"}}},
			"regions/us-central1": map[string]any{"firewallPolicies": []any{map[string]any{"name": "r"}}},
			"regions/empty":       map[string]any{"warning": map[string]any{"code": "NO_RESULTS_ON_PAGE"}},
		}})
	}))
	defer srv.Close()
	c, err := compute.NewNetworkFirewallPoliciesRESTClient(context.Background(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	got, err := NetworkPolicyClient{Client: c}.ListNetworkPolicies(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/compute/v1/projects/p/aggregated/firewallPolicies" || len(got) != 2 {
		t.Fatalf("path %q, got %d policies", path, len(got))
	}
}

func TestHierarchyClientList(t *testing.T) {
	var path, parent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, parent = r.URL.Path, r.URL.Query().Get("parentId")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"name": "org-policy"}}})
	}))
	defer srv.Close()
	c, err := compute.NewFirewallPoliciesRESTClient(context.Background(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	got, err := HierarchyClient{Client: c}.ListHierarchicalPolicies(context.Background(), "organizations/123")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/compute/v1/locations/global/firewallPolicies" || parent != "organizations/123" || len(got) != 1 {
		t.Fatalf("path %q parent %q got %d", path, parent, len(got))
	}
}

// The Cloud Asset call also stops when the context expires.
func TestAssetClientTimesOutOnSlowServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	defer close(release)
	var abandoned atomic.Bool
	c, err := newAssetClient(context.Background(), &abandoned, option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Search(ctx, "organizations/1", assetFirewall); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want context.DeadlineExceeded", err)
	}
	if !abandoned.Load() {
		t.Fatal("Abandoned was not set")
	}
}

func TestBriefDropsErrorDetails(t *testing.T) {
	base := errors.New("googleapi: Error 403: denied\nerror details: name = ErrorInfo reason = X")
	b := brief(base)
	if b.Error() != "googleapi: Error 403: denied" || !errors.Is(b, base) {
		t.Fatalf("brief = %q", b.Error())
	}
	quota := errors.New("googleapi: Error 403: Your application is authenticating by using local Application Default Credentials. The cloudasset.googleapis.com API requires a quota project, which is not set by default.\nerror details: name = ErrorInfo")
	if m := brief(quota).Error(); !strings.Contains(m, "--gcp-quota-project") || strings.Contains(m, "\n") {
		t.Fatalf("quota project error = %q", m)
	}
	plain := errors.New("plain")
	if brief(plain) != plain {
		t.Fatal("an error without details must be returned unchanged")
	}
}

func TestHierarchicalPolicyUsesDisplayName(t *testing.T) {
	open := []string{"0.0.0.0/0"}
	p := policy("475051228768", []string{"organizations/1"}, policyRule(1, "allow", "INGRESS", open, l4("all")))
	p.DisplayName = proto.String("org-policy")
	s := &Scanner{}
	r, ok := s.policyRule(p, "", model.TypeHierarchicalPolicy)
	if !ok || r.Name != "org-policy" || r.Network != "organizations/1" {
		t.Fatalf("rule: %+v ok=%v", r, ok)
	}
}

// Listing by an organization also returns the policies of its folders, and a
// folder search under a folder scope returns the scope itself. Neither may
// produce a finding twice.
func TestHierarchicalPoliciesAreNotReportedTwice(t *testing.T) {
	open := []string{"0.0.0.0/0"}
	folderPolicy := policy("folder-policy", nil, policyRule(1, "allow", "INGRESS", open, l4("tcp", "8084")))
	folderPolicy.SelfLink = proto.String("https://compute/policies/639")
	folderPolicy.Parent = proto.String("folders/111")
	orgPolicy := policy("org-policy", []string{"organizations/9"}, policyRule(1, "allow", "INGRESS", open, l4("tcp", "8082")))
	orgPolicy.SelfLink = proto.String("https://compute/policies/475")
	hier := fakeHierarchy{
		"organizations/9": {policies: []*computepb.FirewallPolicy{orgPolicy, folderPolicy}},
		"folders/111":     {policies: []*computepb.FirewallPolicy{folderPolicy}},
	}
	assets := &fakeAssets{byType: map[string][]Asset{assetFolder: {{Name: "//cloudresourcemanager.googleapis.com/folders/111"}}}}

	got, err := (&Scanner{Scopes: []string{"organizations/9"}, Assets: assets, Hierarchy: hier}).Scan(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatalf("org scope: got %+v, err %v", got, err)
	}
	for _, r := range got {
		if r.Name == "folder-policy" && r.Network != "folders/111" {
			t.Fatalf("an unattached policy shows where it lives: %+v", r)
		}
	}

	// The folder scope returns itself from the folder search.
	got, err = (&Scanner{Scopes: []string{"folders/111"}, Assets: assets, Hierarchy: hier}).Scan(context.Background())
	if err != nil || len(got) != 1 || got[0].Name != "folder-policy" {
		t.Fatalf("folder scope: got %+v, err %v", got, err)
	}
}

type fakeDiscover struct {
	orgs, projects []string
	orgsErr        error
	projectsErr    error
	projectCalls   int
}

func (f *fakeDiscover) Organizations(context.Context) ([]string, error) { return f.orgs, f.orgsErr }
func (f *fakeDiscover) Projects(context.Context) ([]string, error) {
	f.projectCalls++
	return f.projects, f.projectsErr
}

// With no scope given, every organization the caller can see is scanned, and
// the projects are not listed.
func TestDiscoverScansVisibleOrganizations(t *testing.T) {
	open := []string{"0.0.0.0/0"}
	assets := &fakeAssets{byType: map[string][]Asset{
		assetFirewall: {firewallAsset(t, "proj-a", "open", map[string]any{
			"direction": "INGRESS", "sourceRanges": []any{"0.0.0.0/0"},
			"allowed": []any{map[string]any{"IPProtocol": "tcp", "ports": []any{"22"}}}})},
	}}
	d := &fakeDiscover{orgs: []string{"organizations/1", "organizations/2"}}
	s := &Scanner{Discover: d, Assets: assets, Hierarchy: fakeHierarchy{
		"organizations/1": {policies: []*computepb.FirewallPolicy{policy("p1", nil, policyRule(1, "allow", "INGRESS", open, l4("all")))}},
	}}
	got, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.projectCalls != 0 {
		t.Fatal("projects must not be listed when organizations exist")
	}
	scopes := map[string]bool{}
	for _, sc := range assets.scopes {
		scopes[sc] = true
	}
	if !scopes["organizations/1"] || !scopes["organizations/2"] {
		t.Fatalf("scopes searched: %v", assets.scopes)
	}
	// proj-a's firewall is returned by both organizations in this fake: it is reported once.
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
}

// Without an organization the visible projects are scanned instead.
func TestDiscoverFallsBackToProjects(t *testing.T) {
	open := []string{"0.0.0.0/0"}
	d := &fakeDiscover{projects: []string{"p1", "p2"}}
	s := &Scanner{Discover: d, Lister: fakeLister{fws: []*computepb.Firewall{fw("open", "INGRESS", false, open, allow("tcp", "22"))}}}
	got, err := s.Scan(context.Background())
	if err != nil || len(got) != 2 || got[0].Project != "p1" || got[1].Project != "p2" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestDiscoverNothingVisible(t *testing.T) {
	_, err := (&Scanner{Discover: &fakeDiscover{}}).Scan(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no gcp organization or project is visible") {
		t.Fatalf("err = %v", err)
	}
}

func TestDiscoverErrorsAreReported(t *testing.T) {
	boom := errors.New("search denied")
	_, err := (&Scanner{Discover: &fakeDiscover{orgsErr: boom}}).Scan(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("orgs err = %v", err)
	}
	_, err = (&Scanner{Discover: &fakeDiscover{projectsErr: boom}}).Scan(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("projects err = %v", err)
	}
}

// Naming a scope switches discovery off.
func TestExplicitScopeSkipsDiscovery(t *testing.T) {
	d := &fakeDiscover{orgs: []string{"organizations/1"}, projects: []string{"p"}}
	s := &Scanner{Discover: d, Projects: []string{"named"}, Lister: fakeLister{}}
	if _, err := s.Scan(context.Background()); err != nil || d.projectCalls != 0 {
		t.Fatalf("err %v, project discovery calls %d", err, d.projectCalls)
	}
}

// A project that is both named and inside a scanned organization is reported once.
func TestNamedProjectInsideScannedScopeIsNotDuplicated(t *testing.T) {
	assets := &fakeAssets{byType: map[string][]Asset{
		assetFirewall: {firewallAsset(t, "p", "open", map[string]any{
			"direction": "INGRESS", "sourceRanges": []any{"0.0.0.0/0"},
			"network": "https://x/global/networks/default",
			"allowed": []any{map[string]any{"IPProtocol": "tcp", "ports": []any{"22"}}}})},
	}}
	open := []string{"0.0.0.0/0"}
	s := &Scanner{
		Projects: []string{"p"}, Scopes: []string{"organizations/1"}, Assets: assets,
		Lister: fakeLister{fws: []*computepb.Firewall{fw("open", "INGRESS", false, open, allow("tcp", "22"))}},
	}
	got, err := s.Scan(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, err %v", got, err)
	}
}
