// Package gcp lists VPC firewall rules and firewall policies and reports the
// enabled ingress allow rules that are open to the internet.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/detect"
	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// Lister returns every VPC firewall rule of a project, following all pages.
type Lister interface {
	ListFirewalls(ctx context.Context, project string) ([]*computepb.Firewall, error)
}

// NetworkPolicyLister returns the global and regional network firewall
// policies of a project, with their rules.
type NetworkPolicyLister interface {
	ListNetworkPolicies(ctx context.Context, project string) ([]*computepb.FirewallPolicy, error)
}

// HierarchyLister returns the hierarchical firewall policies of an
// organization or folder. parent looks like "organizations/123" or "folders/456".
type HierarchyLister interface {
	ListHierarchicalPolicies(ctx context.Context, parent string) ([]*computepb.FirewallPolicy, error)
}

// Scanner scans a list of projects, or a whole organization or folder.
// Nil policy listers switch policy scanning off.
type Scanner struct {
	Projects        []string // project ids
	Scope           string   // "organizations/ID" or "folders/ID", scanned through Cloud Asset Inventory
	Lister          Lister
	NetworkPolicies NetworkPolicyLister
	Hierarchy       HierarchyLister
	Assets          AssetSearcher
	IncludeIPv6     bool
}

// Options selects what New builds.
type Options struct {
	Projects []string
	Org      string // organization number
	Folder   string // folder number
	Policies bool   // also read network and hierarchical firewall policies
	// QuotaProject is billed for the API calls. User credentials need it for
	// Cloud Asset Inventory. Empty keeps the credentials' own quota project.
	QuotaProject string
	IncludeIPv6  bool
}

// New builds a Scanner with Application Default Credentials. The returned
// close function releases the clients.
func New(ctx context.Context, o Options) (*Scanner, func() error, error) {
	if len(o.Projects) == 0 && o.Org == "" && o.Folder == "" {
		return nil, nil, errors.New("gcp scope is required: use --gcp-project, --gcp-org or --gcp-folder")
	}
	if o.Org != "" && o.Folder != "" {
		return nil, nil, errors.New("use either --gcp-org or --gcp-folder, not both")
	}
	s := &Scanner{Projects: o.Projects, IncludeIPv6: o.IncludeIPv6}
	var copts []option.ClientOption
	if o.QuotaProject != "" {
		copts = append(copts, option.WithQuotaProject(o.QuotaProject))
	}
	abandoned := &atomic.Bool{}
	var closers []func() error
	closeAll := func() error {
		if abandoned.Load() {
			return nil // a timed-out call may still use the clients
		}
		var errs []error
		for _, c := range closers {
			errs = append(errs, c())
		}
		return errors.Join(errs...)
	}
	fail := func(err error) (*Scanner, func() error, error) {
		_ = closeAll()
		return nil, nil, err
	}

	if len(o.Projects) > 0 {
		c, err := compute.NewFirewallsRESTClient(ctx, copts...)
		if err != nil {
			return fail(fmt.Errorf("create gcp firewalls client: %w", err))
		}
		closers = append(closers, c.Close)
		s.Lister = ClientLister{Client: c, Abandoned: abandoned}
	}
	if o.Policies {
		c, err := compute.NewNetworkFirewallPoliciesRESTClient(ctx, copts...)
		if err != nil {
			return fail(fmt.Errorf("create gcp network firewall policies client: %w", err))
		}
		closers = append(closers, c.Close)
		s.NetworkPolicies = NetworkPolicyClient{Client: c, Abandoned: abandoned}
	}
	if o.Org != "" || o.Folder != "" {
		s.Scope = "organizations/" + o.Org
		if o.Folder != "" {
			s.Scope = "folders/" + o.Folder
		}
		a, err := newAssetClient(ctx, abandoned, copts...)
		if err != nil {
			return fail(err)
		}
		closers = append(closers, a.Close)
		s.Assets = a
		if o.Policies {
			h, err := compute.NewFirewallPoliciesRESTClient(ctx, copts...)
			if err != nil {
				return fail(fmt.Errorf("create gcp firewall policies client: %w", err))
			}
			closers = append(closers, h.Close)
			s.Hierarchy = HierarchyClient{Client: h, Abandoned: abandoned}
		}
	}
	return s, closeAll, nil
}

// withContext runs fn in a goroutine and stops waiting when ctx ends. The
// Google compute client builds its HTTP requests without the caller's
// context, so a cancelled or expired context does not stop a call in flight.
// After a timeout the abandoned call ends with the process, and abandoned is
// set so the owner does not close the clients under it.
func withContext[T any](ctx context.Context, abandoned *atomic.Bool, fn func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := fn()
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		if abandoned != nil {
			abandoned.Store(true)
		}
		return zero, ctx.Err()
	}
}

// ClientLister adapts the SDK client to Lister.
type ClientLister struct {
	Client *compute.FirewallsClient
	// Abandoned, when set, is switched on if a call is left running after its
	// context expired. The owner must not close the client then.
	Abandoned *atomic.Bool
}

// ListFirewalls reads all pages from the SDK iterator.
func (l ClientLister) ListFirewalls(ctx context.Context, project string) ([]*computepb.Firewall, error) {
	return withContext(ctx, l.Abandoned, func() ([]*computepb.Firewall, error) {
		it := l.Client.List(ctx, &computepb.ListFirewallsRequest{Project: project})
		var out []*computepb.Firewall
		for {
			fw, err := it.Next()
			if errors.Is(err, iterator.Done) {
				return out, nil
			}
			if err != nil {
				return out, err
			}
			out = append(out, fw)
		}
	})
}

// Scan returns the firewall rules and policy rules that have insecure entries.
// Failures are collected per project and per policy source. The rules found
// before a failure are kept.
func (s *Scanner) Scan(ctx context.Context) ([]model.FirewallRule, error) {
	var out []model.FirewallRule
	var errs []error
	for _, p := range s.Projects {
		rules, err := s.scanProject(ctx, p)
		out = append(out, rules...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if s.Scope != "" {
		rules, err := s.scanScope(ctx)
		out = append(out, rules...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Name < b.Name
	})
	return out, errors.Join(errs...)
}

func (s *Scanner) scanProject(ctx context.Context, project string) ([]model.FirewallRule, error) {
	var out []model.FirewallRule
	var errs []error
	if s.Lister != nil {
		fws, err := s.Lister.ListFirewalls(ctx, project)
		for _, fw := range fws {
			if r, ok := s.vpcRule(fw, project); ok {
				out = append(out, r)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("list firewalls in project %s: %w", project, brief(err)))
		}
	}
	if s.NetworkPolicies != nil {
		rules, err := s.networkPolicyRules(ctx, project)
		out = append(out, rules...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

func (s *Scanner) vpcRule(fw *computepb.Firewall, project string) (model.FirewallRule, bool) {
	r := detect.GCPRule{
		Direction:    fw.GetDirection(),
		Disabled:     fw.GetDisabled(),
		SourceRanges: fw.GetSourceRanges(),
	}
	for _, a := range fw.GetAllowed() {
		r.Allowed = append(r.Allowed, detect.GCPAllowed{Protocol: a.GetIPProtocol(), Ports: a.GetPorts()})
	}
	rules := detect.GCPInsecure(r, s.IncludeIPv6)
	if len(rules) == 0 {
		return model.FirewallRule{}, false
	}
	detect.Sort(rules)
	return model.FirewallRule{
		Name:          fw.GetName(),
		Network:       lastSegment(fw.GetNetwork()),
		Project:       project,
		InsecureRules: rules,
	}, true
}

func (s *Scanner) networkPolicyRules(ctx context.Context, project string) ([]model.FirewallRule, error) {
	policies, err := s.NetworkPolicies.ListNetworkPolicies(ctx, project)
	var out []model.FirewallRule
	for _, p := range policies {
		if r, ok := s.policyRule(p, project, model.TypeNetworkPolicy); ok {
			out = append(out, r)
		}
	}
	if err != nil {
		return out, fmt.Errorf("list network firewall policies in project %s: %w", project, brief(err))
	}
	return out, nil
}

// policyRule converts a policy with at least one insecure rule. Network is
// the list of networks the policy is attached to, or the folder or
// organization for a hierarchical policy.
func (s *Scanner) policyRule(p *computepb.FirewallPolicy, project, typ string) (model.FirewallRule, bool) {
	var rules []model.InsecureRule
	for _, pr := range p.GetRules() {
		r := detect.GCPPolicyRule{
			Priority:    pr.GetPriority(),
			Direction:   pr.GetDirection(),
			Action:      pr.GetAction(),
			Disabled:    pr.GetDisabled(),
			SrcIPRanges: pr.GetMatch().GetSrcIpRanges(),
		}
		for _, l := range pr.GetMatch().GetLayer4Configs() {
			r.Layer4 = append(r.Layer4, detect.GCPAllowed{Protocol: l.GetIpProtocol(), Ports: l.GetPorts()})
		}
		rules = append(rules, detect.GCPPolicyInsecure(r, s.IncludeIPv6)...)
	}
	if len(rules) == 0 {
		return model.FirewallRule{}, false
	}
	detect.Sort(rules)
	var targets []string
	for _, a := range p.GetAssociations() {
		targets = append(targets, lastSegment(a.GetAttachmentTarget()))
	}
	sort.Strings(targets)
	name := p.GetDisplayName() // hierarchical policies have a numeric name
	if name == "" {
		name = p.GetName()
	}
	return model.FirewallRule{
		Name:          name,
		Network:       strings.Join(targets, ","),
		Project:       project,
		Type:          typ,
		InsecureRules: rules,
	}, true
}

func lastSegment(u string) string {
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

// briefError drops the "error details" block that Google API errors append to
// their message. The block repeats the message and adds internal metadata.
type briefError struct {
	msg string
	err error
}

func (e *briefError) Error() string { return e.msg }
func (e *briefError) Unwrap() error { return e.err }

func brief(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "\nerror details:"); i >= 0 {
		return &briefError{msg: msg[:i], err: err}
	}
	return err
}
