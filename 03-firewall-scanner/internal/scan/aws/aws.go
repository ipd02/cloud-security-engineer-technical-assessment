// Package aws lists EC2 security groups and reports inbound rules open to the internet.
package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

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

// OrgAPI is the part of the Organizations client that the scanner uses.
type OrgAPI interface {
	ListAccounts(ctx context.Context, in *organizations.ListAccountsInput, opts ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
}

// AccountFactory returns a client factory that works inside one account.
type AccountFactory func(ctx context.Context, accountID string) (ClientFactory, error)

// Scanner scans one or more regions.
type Scanner struct {
	Factory       ClientFactory
	Regions       []string // explicit regions, or ["all"]
	DefaultRegion string   // used when Regions is empty and for DescribeRegions
	IncludeIPv6   bool

	// Org lists the accounts of the organization. With it set, Scan follows
	// Mode: the active accounts of the organization are scanned through
	// AccountFactory, except the caller's own account, which uses Factory.
	Org            OrgAPI
	AccountFactory AccountFactory
	Mode           string
	// CallerAccount returns the id of the account the credentials belong to.
	CallerAccount func(ctx context.Context) (string, error)
}

// Scope modes. Auto scans the organization when the caller can list its
// accounts, and the caller's own account otherwise.
const (
	ScopeAuto    = "auto"
	ScopeOrg     = "org"
	ScopeAccount = "account"
)

// Options selects what New builds.
type Options struct {
	Regions     string // comma separated list, "all", or empty for the configured default region
	IncludeIPv6 bool
	Scope       string    // ScopeAuto (also when empty), ScopeOrg or ScopeAccount
	RoleName    string    // role assumed in the other accounts of an organization
	Warn        io.Writer // receives a one-line warning when the caller is the root user
}

// orgRegion is the region of the Organizations and STS clients. Both are
// global services, and the regional STS endpoint issues tokens that work in
// opt-in regions too.
const orgRegion = "us-east-1"

// New builds a Scanner with the default AWS credential chain.
func New(ctx context.Context, o Options) (*Scanner, error) {
	// Without a region in the environment or the profile, some credential
	// providers (for example "aws login") cannot refresh their token.
	cfg, err := config.LoadDefaultConfig(ctx, config.WithDefaultRegion(orgRegion))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	s := &Scanner{
		DefaultRegion: cfg.Region,
		IncludeIPv6:   o.IncludeIPv6,
		Factory: func(region string) EC2API {
			c := cfg.Copy()
			c.Region = region
			return ec2.NewFromConfig(c)
		},
	}
	orgCfg := cfg.Copy()
	orgCfg.Region = orgRegion
	var warnOnce sync.Once
	s.CallerAccount = func(ctx context.Context) (string, error) {
		out, err := sts.NewFromConfig(orgCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return "", fmt.Errorf("get caller identity: %w", err)
		}
		warnOnce.Do(func() { warnIfRoot(o.Warn, aws.ToString(out.Arn)) })
		return aws.ToString(out.Account), nil
	}
	s.Mode = o.Scope
	if s.Mode == "" {
		s.Mode = ScopeAuto
	}
	switch s.Mode {
	case ScopeAuto, ScopeOrg:
		if o.RoleName == "" {
			return nil, errors.New("aws role name is required to scan an organization")
		}
		s.Org = organizations.NewFromConfig(orgCfg)
		s.AccountFactory = assumeRoleFactory(cfg, orgCfg, o.RoleName)
	case ScopeAccount:
	default:
		return nil, fmt.Errorf("unknown aws scope %q: use auto, org or account", o.Scope)
	}
	for _, r := range strings.Split(o.Regions, ",") {
		if r = strings.TrimSpace(r); r != "" {
			s.Regions = append(s.Regions, r)
		}
	}
	return s, nil
}

// warnIfRoot tells the user that the scan runs as the account's root user.
func warnIfRoot(w io.Writer, arn string) {
	if w != nil && strings.HasSuffix(arn, ":root") {
		_, _ = fmt.Fprintln(w, "fwscan: warning: running as the AWS root user; use a role with only ec2:DescribeSecurityGroups and ec2:DescribeRegions")
	}
}

// maxParallelRegions bounds concurrent region scans.
const maxParallelRegions = 8

// assumeRoleFactory returns clients that act as the role in each account. The
// role is assumed with a regional STS client, and the credentials are fetched
// at once so a failure shows up for that account.
func assumeRoleFactory(cfg, stsCfg aws.Config, roleName string) AccountFactory {
	return func(ctx context.Context, accountID string) (ClientFactory, error) {
		roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(stsCfg), roleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "fwscan"
		})
		creds := aws.NewCredentialsCache(provider)
		if _, err := creds.Retrieve(ctx); err != nil {
			return nil, fmt.Errorf("assume role %s: %w", roleARN, err)
		}
		return func(region string) EC2API {
			c := cfg.Copy()
			c.Region = region
			c.Credentials = creds
			return ec2.NewFromConfig(c)
		}, nil
	}
}

// maxParallelAccounts bounds concurrent account scans.
const maxParallelAccounts = 8

// Scan returns security groups that have insecure rules. When a region or an
// account fails it still returns the groups from the others, plus a joined error.
func (s *Scanner) Scan(ctx context.Context) ([]model.SecurityGroup, error) {
	if s.Org == nil || s.Mode == ScopeAccount {
		return s.scanCurrentAccount(ctx)
	}
	accounts, err := s.activeAccounts(ctx)
	if err != nil {
		if s.Mode != ScopeOrg && orgUnavailable(err) {
			return s.scanCurrentAccount(ctx)
		}
		return nil, err
	}
	return s.scanOrg(ctx, accounts)
}

// orgUnavailable reports an error that means the credentials cannot list an
// organization: the account has none, or the caller is not allowed to read it.
func orgUnavailable(err error) bool {
	var notInUse *orgtypes.AWSOrganizationsNotInUseException
	if errors.As(err, &notInUse) {
		return true
	}
	var api smithy.APIError
	return errors.As(err, &api) && (api.ErrorCode() == "AccessDeniedException" || api.ErrorCode() == "AWSOrganizationsNotInUseException")
}

// scanCurrentAccount scans the account of the credentials, with those credentials.
func (s *Scanner) scanCurrentAccount(ctx context.Context) ([]model.SecurityGroup, error) {
	groups, err := s.scanRegions(ctx)
	if s.CallerAccount != nil {
		id, idErr := s.CallerAccount(ctx)
		if idErr != nil {
			return groups, errors.Join(err, idErr)
		}
		for i := range groups {
			groups[i].Account = id
		}
	}
	return groups, err
}

// scanOrg scans the given accounts, a few at a time.
func (s *Scanner) scanOrg(ctx context.Context, accounts []string) ([]model.SecurityGroup, error) {
	caller := ""
	if s.CallerAccount != nil {
		caller, _ = s.CallerAccount(ctx) // unknown: every account is then reached through the role
	}
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		groups []model.SecurityGroup
		errs   []error
		sem    = make(chan struct{}, maxParallelAccounts)
	)
	for _, id := range accounts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			g, err := s.scanAccount(ctx, id, id == caller)
			mu.Lock()
			defer mu.Unlock()
			groups = append(groups, g...)
			if err != nil {
				errs = append(errs, fmt.Errorf("account %s: %w", id, err))
			}
		}()
	}
	wg.Wait()

	sort.Slice(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if a.Account != b.Account {
			return a.Account < b.Account
		}
		if a.Region != b.Region {
			return a.Region < b.Region
		}
		return a.ID < b.ID
	})
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return groups, errors.Join(errs...)
}

func (s *Scanner) scanAccount(ctx context.Context, id string, own bool) ([]model.SecurityGroup, error) {
	factory := s.Factory
	if !own {
		var err error
		factory, err = s.AccountFactory(ctx, id)
		if err != nil {
			return nil, err
		}
	}
	sub := &Scanner{Factory: factory, Regions: s.Regions, DefaultRegion: s.DefaultRegion, IncludeIPv6: s.IncludeIPv6}
	groups, err := sub.scanRegions(ctx)
	for i := range groups {
		groups[i].Account = id
	}
	return groups, err
}

// activeAccounts lists the ids of the accounts that are not suspended or closed.
func (s *Scanner) activeAccounts(ctx context.Context) ([]string, error) {
	pager := organizations.NewListAccountsPaginator(s.Org, &organizations.ListAccountsInput{})
	var ids []string
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list organization accounts: %w", err)
		}
		for _, a := range page.Accounts {
			if a.Status == orgtypes.AccountStatusActive {
				ids = append(ids, aws.ToString(a.Id))
			}
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// scanRegions scans the regions of one account.
func (s *Scanner) scanRegions(ctx context.Context) ([]model.SecurityGroup, error) {
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
	region := s.DefaultRegion
	if region == "" {
		region = orgRegion
	}
	out, err := s.Factory(region).DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
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
