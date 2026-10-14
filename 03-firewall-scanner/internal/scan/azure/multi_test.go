package azure

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

// fakeSubs serves pages of subscriptions through a real runtime pager.
type fakeSubs struct {
	pages [][]*armsubscriptions.Subscription
	err   error
}

func (f fakeSubs) NewListPager(*armsubscriptions.ClientListOptions) *runtime.Pager[armsubscriptions.ClientListResponse] {
	i := 0
	return runtime.NewPager(runtime.PagingHandler[armsubscriptions.ClientListResponse]{
		More: func(armsubscriptions.ClientListResponse) bool { return i < len(f.pages) },
		Fetcher: func(context.Context, *armsubscriptions.ClientListResponse) (armsubscriptions.ClientListResponse, error) {
			if f.err != nil {
				return armsubscriptions.ClientListResponse{}, f.err
			}
			page := f.pages[i]
			i++
			return armsubscriptions.ClientListResponse{SubscriptionListResult: armsubscriptions.SubscriptionListResult{Value: page}}, nil
		},
	})
}

func subscription(id string, state armsubscriptions.SubscriptionState) *armsubscriptions.Subscription {
	return &armsubscriptions.Subscription{SubscriptionID: ptr(id), State: &state}
}

// nsgClient returns one page with one open NSG whose id carries the subscription.
type nsgClient struct{ sub string }

func (c nsgClient) NewListAllPager(*armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse] {
	return runtime.NewPager(runtime.PagingHandler[armnetwork.SecurityGroupsClientListAllResponse]{
		More: func(armnetwork.SecurityGroupsClientListAllResponse) bool { return false },
		Fetcher: func(context.Context, *armnetwork.SecurityGroupsClientListAllResponse) (armnetwork.SecurityGroupsClientListAllResponse, error) {
			return armnetwork.SecurityGroupsClientListAllResponse{SecurityGroupListResult: armnetwork.SecurityGroupListResult{
				Value: []*armnetwork.SecurityGroup{nsg("/subscriptions/"+c.sub+"/nsg", rule("any", allow, inbound, star, "*", "*"))},
			}}, nil
		},
	})
}

func TestMultiScanAllAndExplicit(t *testing.T) {
	enabled, disabled := armsubscriptions.SubscriptionStateEnabled, armsubscriptions.SubscriptionStateDisabled
	boom := errors.New("subscription blocked")
	var mu sync.Mutex
	var made []string
	m := &MultiScanner{
		Subscriptions: []string{"sub-c", "sub-a", "sub-a"},
		All:           true,
		List: fakeSubs{pages: [][]*armsubscriptions.Subscription{
			{subscription("sub-b", enabled), subscription("sub-off", disabled), nil},
			{subscription("sub-a", enabled), subscription("sub-d", enabled)},
		}},
		Factory: func(id string) (NSGAPI, error) {
			mu.Lock()
			made = append(made, id)
			mu.Unlock()
			if id == "sub-d" {
				return nil, boom
			}
			return nsgClient{sub: id}, nil
		},
	}
	got, err := m.Scan(context.Background())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "subscription sub-d") {
		t.Fatalf("err = %v", err)
	}
	var ids []string
	for _, n := range got {
		ids = append(ids, n.ID)
	}
	want := "/subscriptions/sub-a/nsg /subscriptions/sub-b/nsg /subscriptions/sub-c/nsg"
	if strings.Join(ids, " ") != want {
		t.Fatalf("got %v; want %s (each subscription once, disabled ones skipped, sorted)", ids, want)
	}
	if len(made) != 4 { // a, b, c and the failing d
		t.Fatalf("clients made for %v", made)
	}
}

func TestMultiListErrorKeepsExplicitSubscriptions(t *testing.T) {
	boom := errors.New("list denied")
	m := &MultiScanner{
		Subscriptions: []string{"sub-a"},
		All:           true,
		List:          fakeSubs{err: boom, pages: [][]*armsubscriptions.Subscription{{}}},
		Factory:       func(id string) (NSGAPI, error) { return nsgClient{sub: id}, nil },
	}
	got, err := m.Scan(context.Background())
	if !errors.Is(err, boom) || len(got) != 1 {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestMultiNoSubscriptionFound(t *testing.T) {
	m := &MultiScanner{All: true, List: fakeSubs{pages: [][]*armsubscriptions.Subscription{{}}}, Factory: func(string) (NSGAPI, error) { return nil, nil }}
	if _, err := m.Scan(context.Background()); err == nil || !strings.Contains(err.Error(), "no enabled azure subscription") {
		t.Fatalf("err = %v", err)
	}
}

// With no subscription named the scanner covers every readable subscription.
func TestNewMultiDefaultsToAllSubscriptions(t *testing.T) {
	m, err := NewMulti(nil, false, false)
	if err != nil {
		t.Skipf("no azure credential chain in this environment: %v", err)
	}
	if !m.All {
		t.Fatal("no subscription named must scan all subscriptions")
	}
	m, err = NewMulti([]string{"sub-a"}, false, false)
	if err != nil || m.All {
		t.Fatalf("a named subscription must not widen the scan: %v, all=%v", err, m != nil && m.All)
	}
}
