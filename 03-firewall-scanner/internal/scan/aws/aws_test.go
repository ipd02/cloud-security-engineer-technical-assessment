package aws

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// fakeEC2 serves the pages for one region and records how often it was called.
type fakeEC2 struct {
	mu      sync.Mutex
	pages   [][]types.SecurityGroup // page i is returned for token "i"
	failAt  int                     // 1-based call number that fails, 0 for never
	err     error
	calls   int
	regions []types.Region
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failAt != 0 && f.calls == f.failAt {
		return nil, f.err
	}
	idx := 0
	if in.NextToken != nil {
		idx = int((*in.NextToken)[0] - '0')
	}
	out := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.pages[idx]}
	if idx+1 < len(f.pages) {
		out.NextToken = aws.String(string(rune('0' + idx + 1)))
	}
	return out, nil
}

func (f *fakeEC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if f.err != nil && f.regions == nil {
		return nil, f.err
	}
	return &ec2.DescribeRegionsOutput{Regions: f.regions}, nil
}

func sg(id, name string, perms ...types.IpPermission) types.SecurityGroup {
	return types.SecurityGroup{GroupId: aws.String(id), GroupName: aws.String(name), IpPermissions: perms}
}

func perm(proto string, from, to int32, cidrs ...string) types.IpPermission {
	p := types.IpPermission{IpProtocol: aws.String(proto), FromPort: aws.Int32(from), ToPort: aws.Int32(to)}
	for _, c := range cidrs {
		p.IpRanges = append(p.IpRanges, types.IpRange{CidrIp: aws.String(c)})
	}
	return p
}

func TestScanPaginationAndFiltering(t *testing.T) {
	f := &fakeEC2{pages: [][]types.SecurityGroup{
		{sg("sg-2", "b", perm("tcp", 22, 22, "0.0.0.0/0")), sg("sg-closed", "closed", perm("tcp", 22, 22, "10.0.0.0/8"))},
		{sg("sg-1", "a", perm("udp", 123, 123, "0.0.0.0/0"), perm("-1", 0, 0, "0.0.0.0/0"))},
		{sg("sg-empty", "empty")},
	}}
	s := &Scanner{Factory: func(string) EC2API { return f }, DefaultRegion: "eu-west-1"}
	got, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 3 {
		t.Fatalf("calls = %d; want 3 pages", f.calls)
	}
	if len(got) != 2 || got[0].ID != "sg-1" || got[1].ID != "sg-2" {
		t.Fatalf("unexpected groups (want sg-1, sg-2 sorted): %+v", got)
	}
	if got[0].Region != "eu-west-1" || len(got[0].InsecureRules) != 2 {
		t.Fatalf("unexpected first group: %+v", got[0])
	}
	// rules sorted: "all" before "udp"
	if got[0].InsecureRules[0].Protocol != "all" || got[0].InsecureRules[1].Protocol != "udp" {
		t.Fatalf("rules not sorted: %+v", got[0].InsecureRules)
	}
}

func TestScanErrorOnSecondPageKeepsFirstPage(t *testing.T) {
	boom := errors.New("throttled")
	f := &fakeEC2{
		pages:  [][]types.SecurityGroup{{sg("sg-1", "a", perm("tcp", 22, 22, "0.0.0.0/0"))}, {}},
		failAt: 2, err: boom,
	}
	s := &Scanner{Factory: func(string) EC2API { return f }, DefaultRegion: "eu-west-1"}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v; want wrapped %v", err, boom)
	}
	if !strings.Contains(err.Error(), "region eu-west-1") {
		t.Fatalf("error lacks region: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want partial result of 1 group, got %d", len(got))
	}
}

func TestScanMultiRegionPartialFailure(t *testing.T) {
	boom := errors.New("access denied")
	good := &fakeEC2{pages: [][]types.SecurityGroup{{sg("sg-a", "a", perm("tcp", 80, 80, "0.0.0.0/0"))}}}
	bad := &fakeEC2{pages: [][]types.SecurityGroup{{}}, failAt: 1, err: boom}
	s := &Scanner{
		Regions: []string{"us-east-1", "eu-west-1"},
		Factory: func(r string) EC2API {
			if r == "eu-west-1" {
				return bad
			}
			return good
		},
	}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "eu-west-1") {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0].Region != "us-east-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestScanAllRegions(t *testing.T) {
	f := &fakeEC2{
		pages:   [][]types.SecurityGroup{{sg("sg-a", "a", perm("tcp", 80, 80, "0.0.0.0/0"))}},
		regions: []types.Region{{RegionName: aws.String("us-east-1")}, {RegionName: aws.String("eu-west-1")}},
	}
	s := &Scanner{Regions: []string{"all"}, DefaultRegion: "us-east-1", Factory: func(string) EC2API { return f }}
	got, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Region != "eu-west-1" || got[1].Region != "us-east-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestScanAllRegionsDescribeFails(t *testing.T) {
	boom := errors.New("no permission")
	f := &fakeEC2{pages: [][]types.SecurityGroup{{}}, err: boom}
	s := &Scanner{Regions: []string{"all"}, DefaultRegion: "us-east-1", Factory: func(string) EC2API { return f }}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) || len(got) != 0 {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

// With no default region the region list is read through us-east-1.
func TestScanAllWithoutDefaultRegionUsesUSEast1(t *testing.T) {
	var asked []string
	var mu sync.Mutex
	s := &Scanner{Regions: []string{"all"}, Factory: func(region string) EC2API {
		mu.Lock()
		asked = append(asked, region)
		mu.Unlock()
		return &fakeEC2{pages: [][]types.SecurityGroup{{}}, regions: []types.Region{{RegionName: aws.String("eu-north-1")}}}
	}}
	if _, err := s.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	sort.Strings(asked)
	if strings.Join(asked, ",") != "eu-north-1,us-east-1" {
		t.Fatalf("regions asked: %v", asked)
	}
}

func TestIPv6Flag(t *testing.T) {
	p := types.IpPermission{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22),
		Ipv6Ranges: []types.Ipv6Range{{CidrIpv6: aws.String("::/0")}}}
	f := &fakeEC2{pages: [][]types.SecurityGroup{{sg("sg-6", "v6", p)}}}
	for _, on := range []bool{false, true} {
		s := &Scanner{DefaultRegion: "r", IncludeIPv6: on, Factory: func(string) EC2API { return f }}
		f.calls = 0
		got, err := s.Scan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if (len(got) == 1) != on {
			t.Fatalf("includeIPv6=%v got %+v", on, got)
		}
	}
}

func TestConvertKeepsModelShape(t *testing.T) {
	g, ok := convert(sg("sg-1", "n", perm("tcp", 1000, 2000, "0.0.0.0/0")), "r", false)
	want := model.InsecureRule{Protocol: "tcp", Port: "1000-2000", Source: "0.0.0.0/0"}
	if !ok || g.InsecureRules[0] != want {
		t.Fatalf("got %+v", g)
	}
}

// ctxEC2 fails like the real SDK when its context is already done.
type ctxEC2 struct{ fakeEC2 }

func (c *ctxEC2) DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput, o ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.fakeEC2.DescribeSecurityGroups(ctx, in, o...)
}

// The context given to Scan reaches the SDK call.
func TestScanHonoursContext(t *testing.T) {
	f := &ctxEC2{fakeEC2{pages: [][]types.SecurityGroup{{sg("sg-1", "a", perm("tcp", 22, 22, "0.0.0.0/0"))}}}}
	s := &Scanner{Factory: func(string) EC2API { return f }, DefaultRegion: "eu-west-1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}

type fakeOrg struct {
	pages [][]orgtypes.Account // page i is returned for token "i"
	err   error
	calls int
}

func (f *fakeOrg) ListAccounts(_ context.Context, in *organizations.ListAccountsInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	idx := 0
	if in.NextToken != nil {
		idx = int((*in.NextToken)[0] - '0')
	}
	out := &organizations.ListAccountsOutput{Accounts: f.pages[idx]}
	if idx+1 < len(f.pages) {
		out.NextToken = aws.String(string(rune('0' + idx + 1)))
	}
	return out, nil
}

func account(id string, status orgtypes.AccountStatus) orgtypes.Account {
	return orgtypes.Account{Id: aws.String(id), Status: status}
}

func TestScanOrg(t *testing.T) {
	boom := errors.New("not authorized to assume")
	org := &fakeOrg{pages: [][]orgtypes.Account{
		{account("333333333333", orgtypes.AccountStatusActive), account("999999999999", orgtypes.AccountStatusSuspended)},
		{account("111111111111", orgtypes.AccountStatusActive), account("222222222222", orgtypes.AccountStatusActive), account("444444444444", orgtypes.AccountStatusPendingClosure)},
	}}
	byAccount := map[string]*fakeEC2{
		"111111111111": {pages: [][]types.SecurityGroup{{sg("sg-b", "b", perm("tcp", 22, 22, "0.0.0.0/0")), sg("sg-closed", "c", perm("tcp", 22, 22, "10.0.0.0/8"))}}},
		"333333333333": {pages: [][]types.SecurityGroup{{sg("sg-a", "a", perm("-1", 0, 0, "0.0.0.0/0"))}}},
	}
	var asked []string
	var mu sync.Mutex
	s := &Scanner{
		Org:           org,
		Regions:       []string{"eu-west-1", "eu-north-1"},
		DefaultRegion: "eu-west-1",
		AccountFactory: func(_ context.Context, id string) (ClientFactory, error) {
			mu.Lock()
			asked = append(asked, id)
			mu.Unlock()
			if id == "222222222222" {
				return nil, boom
			}
			return func(string) EC2API { return byAccount[id] }, nil
		},
	}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "account 222222222222") {
		t.Fatalf("err = %v", err)
	}
	if org.calls != 2 {
		t.Fatalf("ListAccounts calls = %d; want 2 pages", org.calls)
	}
	sort.Strings(asked)
	if strings.Join(asked, ",") != "111111111111,222222222222,333333333333" {
		t.Fatalf("accounts scanned: %v (suspended and closing accounts must be skipped)", asked)
	}
	// Two regions share one fake per account, so each account reports its group once per region.
	var keys []string
	for _, g := range got {
		keys = append(keys, g.Account+"/"+g.Region+"/"+g.ID)
	}
	want := []string{
		"111111111111/eu-north-1/sg-b", "111111111111/eu-west-1/sg-b",
		"333333333333/eu-north-1/sg-a", "333333333333/eu-west-1/sg-a",
	}
	if strings.Join(keys, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v; want %v", keys, want)
	}
}

func TestScanOrgListError(t *testing.T) {
	boom := errors.New("organizations:ListAccounts denied")
	s := &Scanner{Org: &fakeOrg{err: boom}, AccountFactory: func(context.Context, string) (ClientFactory, error) {
		t.Fatal("no account may be scanned when the list fails")
		return nil, nil
	}}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) || len(got) != 0 {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

// One account whose regions partly fail keeps its other groups, tagged with the account.
func TestScanOrgKeepsPartialAccountResults(t *testing.T) {
	boom := errors.New("region blocked")
	org := &fakeOrg{pages: [][]orgtypes.Account{{account("111111111111", orgtypes.AccountStatusActive)}}}
	s := &Scanner{
		Org:           org,
		Regions:       []string{"eu-west-1", "eu-north-1"},
		DefaultRegion: "eu-west-1",
		AccountFactory: func(context.Context, string) (ClientFactory, error) {
			return func(region string) EC2API {
				if region == "eu-north-1" {
					return &fakeEC2{pages: [][]types.SecurityGroup{{}}, failAt: 1, err: boom}
				}
				return &fakeEC2{pages: [][]types.SecurityGroup{{sg("sg-1", "one", perm("tcp", 22, 22, "0.0.0.0/0"))}}}
			}, nil
		},
	}
	got, err := s.Scan(context.Background())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "account 111111111111: region eu-north-1") {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0].Account != "111111111111" || got[0].Region != "eu-west-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	for _, o := range []Options{{Scope: ScopeOrg}, {}, {Scope: "everything", RoleName: "r"}} {
		if _, err := New(context.Background(), o); err == nil {
			t.Fatalf("want an error for %+v", o)
		}
	}
	if _, err := New(context.Background(), Options{Scope: ScopeAccount, Regions: "eu-west-1"}); err != nil {
		t.Fatalf("account scope needs no role: %v", err)
	}
}

func openGroups() *fakeEC2 {
	return &fakeEC2{pages: [][]types.SecurityGroup{{sg("sg-1", "one", perm("tcp", 22, 22, "0.0.0.0/0"))}}}
}

func callerIs(id string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return id, nil }
}

// Auto mode scans the caller's own account when it cannot list an organization.
func TestScanAutoFallsBackToCurrentAccount(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not the management account"}
	for name, listErr := range map[string]error{
		"no organization": &orgtypes.AWSOrganizationsNotInUseException{},
		"access denied":   denied,
	} {
		t.Run(name, func(t *testing.T) {
			org := &fakeOrg{err: listErr}
			s := &Scanner{
				Org: org, Mode: ScopeAuto, Factory: func(string) EC2API { return openGroups() }, DefaultRegion: "eu-west-1",
				CallerAccount: callerIs("111111111111"),
				AccountFactory: func(context.Context, string) (ClientFactory, error) {
					t.Fatal("no role may be assumed for the caller's own account")
					return nil, nil
				},
			}
			got, err := s.Scan(context.Background())
			if err != nil || len(got) != 1 || got[0].Account != "111111111111" || org.calls != 1 {
				t.Fatalf("got %+v, err %v, list calls %d", got, err, org.calls)
			}
		})
	}
}

// Any other list error is not hidden by the fallback, and org mode never falls back.
func TestScanAutoDoesNotHideOtherErrors(t *testing.T) {
	boom := errors.New("throttled")
	s := &Scanner{Org: &fakeOrg{err: boom}, Mode: ScopeAuto, Factory: func(string) EC2API { return openGroups() }, DefaultRegion: "eu-west-1"}
	if got, err := s.Scan(context.Background()); !errors.Is(err, boom) || len(got) != 0 {
		t.Fatalf("got %+v, err %v", got, err)
	}
	s = &Scanner{Org: &fakeOrg{err: &orgtypes.AWSOrganizationsNotInUseException{}}, Mode: ScopeOrg, Factory: func(string) EC2API { return openGroups() }, DefaultRegion: "eu-west-1"}
	if got, err := s.Scan(context.Background()); err == nil || len(got) != 0 {
		t.Fatalf("org mode must report the missing organization: got %+v, err %v", got, err)
	}
}

func TestScanAccountModeNeverListsTheOrganization(t *testing.T) {
	org := &fakeOrg{err: errors.New("must not be called")}
	s := &Scanner{Org: org, Mode: ScopeAccount, Factory: func(string) EC2API { return openGroups() }, DefaultRegion: "eu-west-1", CallerAccount: callerIs("222222222222")}
	got, err := s.Scan(context.Background())
	if err != nil || org.calls != 0 || len(got) != 1 || got[0].Account != "222222222222" {
		t.Fatalf("got %+v, err %v, list calls %d", got, err, org.calls)
	}
}

// In an organization the caller's own account uses the caller's credentials,
// and the other accounts are reached through the role.
func TestScanOrgUsesOwnCredentialsForTheCallersAccount(t *testing.T) {
	org := &fakeOrg{pages: [][]orgtypes.Account{{account("111111111111", orgtypes.AccountStatusActive), account("222222222222", orgtypes.AccountStatusActive)}}}
	var assumed []string
	s := &Scanner{
		Org: org, Mode: ScopeAuto, DefaultRegion: "eu-west-1", Regions: []string{"eu-west-1"},
		Factory:       func(string) EC2API { return openGroups() },
		CallerAccount: callerIs("111111111111"),
		AccountFactory: func(_ context.Context, id string) (ClientFactory, error) {
			assumed = append(assumed, id)
			return func(string) EC2API { return openGroups() }, nil
		},
	}
	got, err := s.Scan(context.Background())
	if err != nil || len(got) != 2 || strings.Join(assumed, ",") != "222222222222" {
		t.Fatalf("got %+v, err %v, assumed %v", got, err, assumed)
	}
}

func TestWarnIfRoot(t *testing.T) {
	var b strings.Builder
	warnIfRoot(&b, "arn:aws:iam::111111111111:root")
	if !strings.Contains(b.String(), "root user") || strings.Count(b.String(), "\n") != 1 {
		t.Fatalf("warning = %q", b.String())
	}
	b.Reset()
	warnIfRoot(&b, "arn:aws:sts::111111111111:assumed-role/fwscan-reader/fwscan")
	warnIfRoot(&b, "arn:aws:iam::111111111111:user/ci")
	warnIfRoot(nil, "arn:aws:iam::111111111111:root") // no writer: no output and no panic
	if b.Len() != 0 {
		t.Fatalf("no warning expected, got %q", b.String())
	}
}
