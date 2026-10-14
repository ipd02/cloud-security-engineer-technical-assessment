package azure

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// SubscriptionAPI is the part of the subscriptions client that the scanner uses.
type SubscriptionAPI interface {
	NewListPager(options *armsubscriptions.ClientListOptions) *runtime.Pager[armsubscriptions.ClientListResponse]
}

// ClientFactory returns the NSG client of one subscription.
type ClientFactory func(subscriptionID string) (NSGAPI, error)

// MultiScanner scans several subscriptions, a few at a time.
type MultiScanner struct {
	Subscriptions []string // explicit subscription ids
	All           bool     // also scan every enabled subscription the credential can read
	List          SubscriptionAPI
	Factory       ClientFactory
	IncludeIPv6   bool
}

// maxParallelSubscriptions bounds concurrent subscription scans.
const maxParallelSubscriptions = 8

// NewMulti builds a MultiScanner with DefaultAzureCredential.
func NewMulti(subscriptions []string, all, includeIPv6 bool) (*MultiScanner, error) {
	if len(subscriptions) == 0 && !all {
		return nil, errors.New("azure subscription is required: use --azure-subscription or --azure-all-subscriptions")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	list, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure subscriptions client: %w", err)
	}
	return &MultiScanner{
		Subscriptions: subscriptions,
		All:           all,
		List:          list,
		IncludeIPv6:   includeIPv6,
		Factory: func(id string) (NSGAPI, error) {
			return armnetwork.NewSecurityGroupsClient(id, cred, nil)
		},
	}, nil
}

// Scan returns the NSGs with insecure rules of every selected subscription.
// A subscription that fails is reported and the others still return results.
func (m *MultiScanner) Scan(ctx context.Context) ([]model.NSG, error) {
	var errs []error
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, id := range m.Subscriptions {
		add(id)
	}
	if m.All {
		listed, err := m.enabledSubscriptions(ctx)
		if err != nil {
			errs = append(errs, err)
		}
		for _, id := range listed {
			add(id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("no enabled azure subscription found"))
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		nsgs []model.NSG
		sem  = make(chan struct{}, maxParallelSubscriptions)
	)
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			found, err := m.scanSubscription(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			nsgs = append(nsgs, found...)
			if err != nil {
				errs = append(errs, fmt.Errorf("subscription %s: %w", id, err))
			}
		}()
	}
	wg.Wait()

	sort.Slice(nsgs, func(i, j int) bool { return nsgs[i].ID < nsgs[j].ID })
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return nsgs, errors.Join(errs...)
}

func (m *MultiScanner) scanSubscription(ctx context.Context, id string) ([]model.NSG, error) {
	client, err := m.Factory(id)
	if err != nil {
		return nil, fmt.Errorf("create azure nsg client: %w", err)
	}
	return (&Scanner{Client: client, IncludeIPv6: m.IncludeIPv6}).Scan(ctx)
}

// enabledSubscriptions lists the ids of the subscriptions in the Enabled state.
func (m *MultiScanner) enabledSubscriptions(ctx context.Context) ([]string, error) {
	pager := m.List.NewListPager(nil)
	var ids []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return ids, fmt.Errorf("list azure subscriptions: %w", brief(err))
		}
		for _, s := range page.Value {
			if s != nil && s.State != nil && *s.State == armsubscriptions.SubscriptionStateEnabled {
				ids = append(ids, str(s.SubscriptionID))
			}
		}
	}
	return ids, nil
}
