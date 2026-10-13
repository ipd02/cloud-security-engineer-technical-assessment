// Package gcp lists VPC firewall rules and reports enabled ingress allow rules open to the internet.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/detect"
	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// Lister returns every firewall rule of a project, following all pages.
type Lister interface {
	ListFirewalls(ctx context.Context, project string) ([]*computepb.Firewall, error)
}

// Scanner scans one project.
type Scanner struct {
	Lister      Lister
	Project     string
	IncludeIPv6 bool
}

// New builds a Scanner with Application Default Credentials. The returned
// close function releases the client.
func New(ctx context.Context, project string, includeIPv6 bool) (*Scanner, func() error, error) {
	if project == "" {
		return nil, nil, errors.New("gcp project is required: use --gcp-project")
	}
	c, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("create gcp firewalls client: %w", err)
	}
	return &Scanner{Lister: ClientLister{Client: c}, Project: project, IncludeIPv6: includeIPv6}, c.Close, nil
}

// ClientLister adapts the SDK client to Lister.
type ClientLister struct {
	Client *compute.FirewallsClient
}

// ListFirewalls reads all pages from the SDK iterator.
func (l ClientLister) ListFirewalls(ctx context.Context, project string) ([]*computepb.Firewall, error) {
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
}

// Scan returns firewall rules that have insecure entries.
func (s *Scanner) Scan(ctx context.Context) ([]model.FirewallRule, error) {
	fws, err := s.Lister.ListFirewalls(ctx, s.Project)
	if err != nil {
		return nil, fmt.Errorf("list firewalls in project %s: %w", s.Project, err)
	}
	var out []model.FirewallRule
	for _, fw := range fws {
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
			continue
		}
		detect.Sort(rules)
		out = append(out, model.FirewallRule{
			Name:          fw.GetName(),
			Network:       lastSegment(fw.GetNetwork()),
			Project:       s.Project,
			InsecureRules: rules,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func lastSegment(u string) string {
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}
