package gcp

import (
	"context"
	"errors"
	"sync/atomic"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/proto"
)

// NetworkPolicyClient adapts the SDK client to NetworkPolicyLister.
type NetworkPolicyClient struct {
	Client    *compute.NetworkFirewallPoliciesClient
	Abandoned *atomic.Bool
}

// ListNetworkPolicies returns the global and regional policies of a project.
// The aggregated list covers every region in one call.
func (c NetworkPolicyClient) ListNetworkPolicies(ctx context.Context, project string) ([]*computepb.FirewallPolicy, error) {
	return withContext(ctx, c.Abandoned, func() ([]*computepb.FirewallPolicy, error) {
		it := c.Client.AggregatedList(ctx, &computepb.AggregatedListNetworkFirewallPoliciesRequest{Project: project})
		var out []*computepb.FirewallPolicy
		for {
			pair, err := it.Next()
			if errors.Is(err, iterator.Done) {
				return out, nil
			}
			if err != nil {
				return out, err
			}
			out = append(out, pair.Value.GetFirewallPolicies()...)
		}
	})
}

// HierarchyClient adapts the SDK client to HierarchyLister.
type HierarchyClient struct {
	Client    *compute.FirewallPoliciesClient
	Abandoned *atomic.Bool
}

// ListHierarchicalPolicies returns the policies that belong to an
// organization or folder.
func (c HierarchyClient) ListHierarchicalPolicies(ctx context.Context, parent string) ([]*computepb.FirewallPolicy, error) {
	return withContext(ctx, c.Abandoned, func() ([]*computepb.FirewallPolicy, error) {
		it := c.Client.List(ctx, &computepb.ListFirewallPoliciesRequest{ParentId: proto.String(parent)})
		var out []*computepb.FirewallPolicy
		for {
			p, err := it.Next()
			if errors.Is(err, iterator.Done) {
				return out, nil
			}
			if err != nil {
				return out, err
			}
			out = append(out, p)
		}
	})
}
