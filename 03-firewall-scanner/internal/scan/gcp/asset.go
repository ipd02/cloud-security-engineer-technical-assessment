package gcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// Cloud Asset Inventory types used by the organization and folder scope.
const (
	assetFirewall = "compute.googleapis.com/Firewall"
	assetProject  = "cloudresourcemanager.googleapis.com/Project"
	assetFolder   = "cloudresourcemanager.googleapis.com/Folder"
)

// Asset is the part of a Cloud Asset Inventory search result that the scanner uses.
type Asset struct {
	Name        string // full resource name, //service.googleapis.com/...
	DisplayName string
	Attributes  *structpb.Struct // additionalAttributes
	Resource    *structpb.Struct // data of the first versioned resource
}

// AssetSearcher lists the assets of one type under an organization or folder.
type AssetSearcher interface {
	Search(ctx context.Context, scope, assetType string) ([]Asset, error)
}

type assetClient struct {
	c         *asset.Client
	abandoned *atomic.Bool
}

func newAssetClient(ctx context.Context, abandoned *atomic.Bool, opts ...option.ClientOption) (*assetClient, error) {
	c, err := asset.NewRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create gcp asset client: %w", err)
	}
	return &assetClient{c: c, abandoned: abandoned}, nil
}

func (a *assetClient) Close() error { return a.c.Close() }

// Search follows all result pages for one asset type.
func (a *assetClient) Search(ctx context.Context, scope, assetType string) ([]Asset, error) {
	return withContext(ctx, a.abandoned, func() ([]Asset, error) {
		it := a.c.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
			Scope:      scope,
			AssetTypes: []string{assetType},
			ReadMask: &fieldmaskpb.FieldMask{Paths: []string{
				"name", "asset_type", "display_name", "additional_attributes", "versioned_resources",
			}},
		})
		var out []Asset
		for {
			r, err := it.Next()
			if errors.Is(err, iterator.Done) {
				return out, nil
			}
			if err != nil {
				return out, err
			}
			as := Asset{Name: r.GetName(), DisplayName: r.GetDisplayName(), Attributes: r.GetAdditionalAttributes()}
			if vr := r.GetVersionedResources(); len(vr) > 0 {
				as.Resource = vr[0].GetResource()
			}
			out = append(out, as)
		}
	})
}

// scanScope reads every VPC firewall rule under the scope from Cloud Asset
// Inventory. With policy listers set it also reads the hierarchical policies
// of the scope and its folders, and the network policies of every project.
func (s *Scanner) scanScope(ctx context.Context) ([]model.FirewallRule, error) {
	var out []model.FirewallRule
	var errs []error

	assets, err := s.Assets.Search(ctx, s.Scope, assetFirewall)
	if err != nil {
		errs = append(errs, fmt.Errorf("search firewalls in %s: %w", s.Scope, brief(err)))
	}
	for _, a := range assets {
		fw, err := firewallFromAsset(a)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if r, ok := s.vpcRule(fw, projectFromName(a.Name)); ok {
			out = append(out, r)
		}
	}

	if s.Hierarchy != nil {
		rules, err := s.hierarchicalRules(ctx)
		out = append(out, rules...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if s.NetworkPolicies != nil {
		rules, err := s.scopeNetworkPolicies(ctx)
		out = append(out, rules...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

func (s *Scanner) hierarchicalRules(ctx context.Context) ([]model.FirewallRule, error) {
	var out []model.FirewallRule
	var errs []error
	parents := []string{s.Scope}
	folders, err := s.Assets.Search(ctx, s.Scope, assetFolder)
	if err != nil {
		errs = append(errs, fmt.Errorf("search folders in %s: %w", s.Scope, brief(err)))
	}
	for _, f := range folders {
		if i := strings.LastIndex(f.Name, "/folders/"); i >= 0 {
			parents = append(parents, "folders/"+f.Name[i+len("/folders/"):])
		}
	}
	sort.Strings(parents[1:])
	for _, parent := range parents {
		policies, err := s.Hierarchy.ListHierarchicalPolicies(ctx, parent)
		for _, p := range policies {
			if r, ok := s.policyRule(p, "", model.TypeHierarchicalPolicy); ok {
				out = append(out, r)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("list hierarchical firewall policies of %s: %w", parent, brief(err)))
		}
	}
	return out, errors.Join(errs...)
}

func (s *Scanner) scopeNetworkPolicies(ctx context.Context) ([]model.FirewallRule, error) {
	var out []model.FirewallRule
	var errs []error
	projects, err := s.Assets.Search(ctx, s.Scope, assetProject)
	if err != nil {
		errs = append(errs, fmt.Errorf("search projects in %s: %w", s.Scope, brief(err)))
	}
	for _, p := range projects {
		id := projectID(p)
		if id == "" {
			errs = append(errs, fmt.Errorf("project asset %s has no project id", p.Name))
			continue
		}
		rules, err := s.networkPolicyRules(ctx, id)
		out = append(out, rules...)
		if err != nil && !computeDisabled(err) {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

// computeDisabled reports the error of a project whose Compute Engine API is
// off. Such a project has no network firewall policies.
func computeDisabled(err error) bool {
	m := err.Error()
	return strings.Contains(m, "SERVICE_DISABLED") || strings.Contains(m, "has not been used in project")
}

// firewallFromAsset decodes the versioned resource of a Firewall asset. The
// data has the same JSON shape as the Compute Engine REST resource.
func firewallFromAsset(a Asset) (*computepb.Firewall, error) {
	if a.Resource == nil {
		return nil, fmt.Errorf("asset %s has no resource data", a.Name)
	}
	b, err := protojson.Marshal(a.Resource)
	if err != nil {
		return nil, fmt.Errorf("asset %s: %w", a.Name, err)
	}
	fw := &computepb.Firewall{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, fw); err != nil {
		return nil, fmt.Errorf("asset %s: %w", a.Name, err)
	}
	if fw.Name == nil {
		fw.Name = proto.String(lastSegment(a.Name))
	}
	return fw, nil
}

// projectFromName returns the project id of //compute.googleapis.com/projects/ID/global/firewalls/NAME.
func projectFromName(name string) string {
	_, rest, ok := strings.Cut(name, "/projects/")
	if !ok {
		return ""
	}
	id, _, _ := strings.Cut(rest, "/")
	return id
}

// projectID reads the project id of a project asset: the projectId attribute,
// else the last part of //cloudresourcemanager.googleapis.com/projects/ID. The
// display name is the project's friendly name, not its id.
func projectID(a Asset) string {
	if v := a.Attributes.GetFields()["projectId"].GetStringValue(); v != "" {
		return v
	}
	if _, id, ok := strings.Cut(a.Name, "/projects/"); ok && !strings.Contains(id, "/") {
		return id
	}
	return ""
}
