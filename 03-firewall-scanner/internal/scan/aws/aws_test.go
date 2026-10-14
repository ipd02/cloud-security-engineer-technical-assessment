package aws

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

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

func TestScanAllWithoutDefaultRegion(t *testing.T) {
	s := &Scanner{Regions: []string{"all"}, Factory: func(string) EC2API { return &fakeEC2{} }}
	if _, err := s.Scan(context.Background()); err == nil {
		t.Fatal("want error")
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
