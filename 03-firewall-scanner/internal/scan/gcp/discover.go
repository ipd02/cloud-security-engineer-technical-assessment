package gcp

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"google.golang.org/api/iterator"
)

// Discoverer finds what the credentials can scan when no scope is given.
type Discoverer interface {
	// Organizations returns the organizations the caller can see, as "organizations/ID".
	Organizations(ctx context.Context) ([]string, error)
	// Projects returns the ids of the active projects the caller can see.
	Projects(ctx context.Context) ([]string, error)
}

// ResourceManagerClient adapts the Resource Manager clients to Discoverer.
type ResourceManagerClient struct {
	Orgs      *resourcemanager.OrganizationsClient
	ProjectsC *resourcemanager.ProjectsClient
	Abandoned *atomic.Bool
}

// Organizations lists the organizations visible to the caller.
func (c ResourceManagerClient) Organizations(ctx context.Context) ([]string, error) {
	return withContext(ctx, c.Abandoned, func() ([]string, error) {
		it := c.Orgs.SearchOrganizations(ctx, &resourcemanagerpb.SearchOrganizationsRequest{})
		var out []string
		for {
			o, err := it.Next()
			if errors.Is(err, iterator.Done) {
				return out, nil
			}
			if err != nil {
				return out, fmt.Errorf("search organizations: %w", brief(err))
			}
			out = append(out, o.GetName())
		}
	})
}

// Projects lists the active projects visible to the caller.
func (c ResourceManagerClient) Projects(ctx context.Context) ([]string, error) {
	return withContext(ctx, c.Abandoned, func() ([]string, error) {
		it := c.ProjectsC.SearchProjects(ctx, &resourcemanagerpb.SearchProjectsRequest{})
		var out []string
		for {
			p, err := it.Next()
			if errors.Is(err, iterator.Done) {
				return out, nil
			}
			if err != nil {
				return out, fmt.Errorf("search projects: %w", brief(err))
			}
			if p.GetState() == resourcemanagerpb.Project_ACTIVE {
				out = append(out, p.GetProjectId())
			}
		}
	})
}
