package azure

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7/fake"
)

func ptr[T any](v T) *T { return &v }

func rule(name string, access armnetwork.SecurityRuleAccess, dir armnetwork.SecurityRuleDirection,
	proto armnetwork.SecurityRuleProtocol, src string, port string) *armnetwork.SecurityRule {
	return &armnetwork.SecurityRule{Name: ptr(name), Properties: &armnetwork.SecurityRulePropertiesFormat{
		Access: &access, Direction: &dir, Protocol: &proto,
		SourceAddressPrefix: ptr(src), DestinationPortRange: ptr(port),
	}}
}

func nsg(id string, rules ...*armnetwork.SecurityRule) *armnetwork.SecurityGroup {
	return &armnetwork.SecurityGroup{
		ID: ptr(id), Name: ptr("n-" + id), Location: ptr("westeurope"),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: rules},
	}
}

const (
	allow   = armnetwork.SecurityRuleAccessAllow
	deny    = armnetwork.SecurityRuleAccessDeny
	inbound = armnetwork.SecurityRuleDirectionInbound
	out     = armnetwork.SecurityRuleDirectionOutbound
	star    = armnetwork.SecurityRuleProtocolAsterisk
	tcp     = armnetwork.SecurityRuleProtocolTCP
)

// scannerFor builds a Scanner whose client talks to the SDK's in-memory fake server.
func scannerFor(t *testing.T, srv fake.SecurityGroupsServer) *Scanner {
	t.Helper()
	s, err := NewWithCredential("sub", &azfake.TokenCredential{}, false, &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Transport: fake.NewSecurityGroupsServerTransport(&srv),
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScanPaginationAndFiltering(t *testing.T) {
	var srv fake.SecurityGroupsServer
	srv.NewListAllPager = func(*armnetwork.SecurityGroupsClientListAllOptions) azfake.PagerResponder[armnetwork.SecurityGroupsClientListAllResponse] {
		var r azfake.PagerResponder[armnetwork.SecurityGroupsClientListAllResponse]
		r.AddPage(http.StatusOK, armnetwork.SecurityGroupsClientListAllResponse{SecurityGroupListResult: armnetwork.SecurityGroupListResult{
			Value: []*armnetwork.SecurityGroup{
				nsg("/z", rule("ssh", allow, inbound, tcp, "Internet", "22")),
				nsg("/closed", rule("vnet", allow, inbound, star, "VirtualNetwork", "*")),
			}}}, nil)
		r.AddPage(http.StatusOK, armnetwork.SecurityGroupsClientListAllResponse{SecurityGroupListResult: armnetwork.SecurityGroupListResult{
			Value: []*armnetwork.SecurityGroup{
				nsg("/a",
					rule("any", allow, inbound, star, "*", "*"),
					rule("denied", deny, inbound, star, "*", "*"),
					rule("egress", allow, out, star, "*", "*")),
				{ID: ptr("/nil-props")},
			}}}, nil)
		return r
	}
	got, err := scannerFor(t, srv).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "/a" || got[1].ID != "/z" {
		t.Fatalf("got %+v", got)
	}
	if len(got[0].InsecureRules) != 1 || got[0].InsecureRules[0].RuleID != "any" {
		t.Fatalf("rules: %+v", got[0].InsecureRules)
	}
	if r := got[1].InsecureRules[0]; r.Protocol != "tcp" || r.Port != "22" || r.Source != "Internet" {
		t.Fatalf("rule: %+v", r)
	}
}

func TestScanListsAndRangeLists(t *testing.T) {
	var srv fake.SecurityGroupsServer
	srv.NewListAllPager = func(*armnetwork.SecurityGroupsClientListAllOptions) azfake.PagerResponder[armnetwork.SecurityGroupsClientListAllResponse] {
		var r azfake.PagerResponder[armnetwork.SecurityGroupsClientListAllResponse]
		sr := rule("multi", allow, inbound, tcp, "", "")
		sr.Properties.SourceAddressPrefix = nil
		sr.Properties.DestinationPortRange = nil
		sr.Properties.SourceAddressPrefixes = []*string{ptr("10.0.0.0/8"), ptr("0.0.0.0/0")}
		sr.Properties.DestinationPortRanges = []*string{ptr("80"), ptr("8000-8100")}
		r.AddPage(http.StatusOK, armnetwork.SecurityGroupsClientListAllResponse{SecurityGroupListResult: armnetwork.SecurityGroupListResult{
			Value: []*armnetwork.SecurityGroup{nsg("/m", sr)}}}, nil)
		return r
	}
	got, err := scannerFor(t, srv).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].InsecureRules) != 2 ||
		got[0].InsecureRules[0].Port != "80" || got[0].InsecureRules[1].Port != "8000-8100" {
		t.Fatalf("got %+v", got)
	}
}

func TestScanErrorKeepsEarlierPages(t *testing.T) {
	boom := errors.New("authorization failed")
	var srv fake.SecurityGroupsServer
	srv.NewListAllPager = func(*armnetwork.SecurityGroupsClientListAllOptions) azfake.PagerResponder[armnetwork.SecurityGroupsClientListAllResponse] {
		var r azfake.PagerResponder[armnetwork.SecurityGroupsClientListAllResponse]
		r.AddPage(http.StatusOK, armnetwork.SecurityGroupsClientListAllResponse{SecurityGroupListResult: armnetwork.SecurityGroupListResult{
			Value: []*armnetwork.SecurityGroup{nsg("/a", rule("any", allow, inbound, star, "*", "*"))}}}, nil)
		r.AddError(boom)
		return r
	}
	got, err := scannerFor(t, srv).Scan(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	if len(got) != 1 {
		t.Fatalf("want first page kept, got %+v", got)
	}
}

func TestNewRequiresSubscription(t *testing.T) {
	if _, err := New("", false); err == nil {
		t.Fatal("want error for empty subscription")
	}
}

// ctxTransport fails like a real HTTP transport when the request context is done.
type ctxTransport struct{}

func (ctxTransport) Do(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"value":[]}`)), Request: r}, nil
}

// The context given to Scan reaches the SDK call.
func TestScanHonoursContext(t *testing.T) {
	s, err := NewWithCredential("sub", &azfake.TokenCredential{}, false, &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{Transport: ctxTransport{}, Retry: policy.RetryOptions{MaxRetries: -1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}

// A denied call is reported as the status and the Azure error code, without the
// request URL, the response body or the caller's identity.
func TestScanErrorIsBrief(t *testing.T) {
	var srv fake.SecurityGroupsServer
	srv.NewListAllPager = func(*armnetwork.SecurityGroupsClientListAllOptions) azfake.PagerResponder[armnetwork.SecurityGroupsClientListAllResponse] {
		var r azfake.PagerResponder[armnetwork.SecurityGroupsClientListAllResponse]
		r.AddResponseError(http.StatusForbidden, "AuthorizationFailed")
		return r
	}
	_, err := scannerFor(t, srv).Scan(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 403 AuthorizationFailed") || strings.Contains(err.Error(), "\n") {
		t.Fatalf("err = %v", err)
	}
	var re *azcore.ResponseError
	if !errors.As(err, &re) {
		t.Fatal("the SDK error must stay in the chain")
	}
}
