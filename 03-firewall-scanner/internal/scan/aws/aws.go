// Package aws lists EC2 security groups and reports inbound rules open to the internet.
package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/detect"
	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// EC2API is the part of the EC2 client that the scanner uses.
type EC2API interface {
	DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput, opts ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// ClientFactory returns a client for one region.
type ClientFactory func(region string) EC2API

// Scanner scans one or more regions.
type Scanner struct {
	Factory       ClientFactory
	Regions       []string // explicit regions, or ["all"]
	DefaultRegion string   // used when Regions is empty and for DescribeRegions
	IncludeIPv6   bool
}

// New builds a Scanner with the default AWS credential chain. regions is a
// comma separated list, "all", or empty for the configured default region.
func New(ctx context.Context, regions string, includeIPv6 bool) (*Scanner, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	s := &Scanner{
		DefaultRegion: cfg.Region,
		IncludeIPv6:   includeIPv6,
		Factory: func(region string) EC2API {
			c := cfg.Copy()
			c.Region = region
			return ec2.NewFromConfig(c)
		},
	}
	for _, r := range strings.Split(regions, ",") {
		if r = strings.TrimSpace(r); r != "" {
			s.Regions = append(s.Regions, r)
		}
	}
	if len(s.Regions) == 0 && s.DefaultRegion == "" {
		return nil, errors.New("no aws region: set AWS_REGION or use --aws-regions")
	}
	return s, nil
}

// maxParallelRegions bounds concurrent region scans.
const maxParallelRegions = 8

// Scan returns security groups that have insecure rules. When a region fails
// it still returns the groups from the other regions, plus a joined error.
func (s *Scanner) Scan(ctx context.Context) ([]model.SecurityGroup, error) {
	regions := s.Regions
	if len(regions) == 0 {
		regions = []string{s.DefaultRegion}
	}
	if len(regions) == 1 && strings.EqualFold(regions[0], "all") {
		all, err := s.listRegions(ctx)
		if err != nil {
			return nil, err
		}
		regions = all
	}

	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		groups []model.SecurityGroup
		errs   []error
		sem    = make(chan struct{}, maxParallelRegions)
	)
	for _, region := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			g, err := s.scanRegion(ctx, region)
			mu.Lock()
			defer mu.Unlock()
			groups = append(groups, g...)
			if err != nil {
				errs = append(errs, fmt.Errorf("region %s: %w", region, err))
			}
		}()
	}
	wg.Wait()

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Region != groups[j].Region {
			return groups[i].Region < groups[j].Region
		}
		return groups[i].ID < groups[j].ID
	})
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return groups, errors.Join(errs...)
}

func (s *Scanner) listRegions(ctx context.Context) ([]string, error) {
	if s.DefaultRegion == "" {
		return nil, errors.New("describe regions: no default region configured")
	}
	out, err := s.Factory(s.DefaultRegion).DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe regions: %w", err)
	}
	var names []string
	for _, r := range out.Regions {
		names = append(names, aws.ToString(r.RegionName))
	}
	sort.Strings(names)
	return names, nil
}

func (s *Scanner) scanRegion(ctx context.Context, region string) ([]model.SecurityGroup, error) {
	pager := ec2.NewDescribeSecurityGroupsPaginator(s.Factory(region), &ec2.DescribeSecurityGroupsInput{})
	var groups []model.SecurityGroup
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return groups, fmt.Errorf("describe security groups: %w", err)
		}
		for _, sg := range page.SecurityGroups {
			if g, ok := convert(sg, region, s.IncludeIPv6); ok {
				groups = append(groups, g)
			}
		}
	}
	return groups, nil
}

func convert(sg types.SecurityGroup, region string, includeIPv6 bool) (model.SecurityGroup, bool) {
	var rules []model.InsecureRule
	for _, p := range sg.IpPermissions {
		r := detect.AWSRule{
			Protocol: aws.ToString(p.IpProtocol),
			From:     p.FromPort,
			To:       p.ToPort,
		}
		for _, c := range p.IpRanges {
			r.IPv4 = append(r.IPv4, aws.ToString(c.CidrIp))
		}
		for _, c := range p.Ipv6Ranges {
			r.IPv6 = append(r.IPv6, aws.ToString(c.CidrIpv6))
		}
		rules = append(rules, detect.AWSInsecure(r, includeIPv6)...)
	}
	if len(rules) == 0 {
		return model.SecurityGroup{}, false
	}
	detect.Sort(rules)
	return model.SecurityGroup{
		ID:            aws.ToString(sg.GroupId),
		Name:          aws.ToString(sg.GroupName),
		Region:        region,
		InsecureRules: rules,
	}, true
}
