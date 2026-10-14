// Command fwscan reports inbound rules open to the internet in AWS, GCP and Azure.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/mock"
	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/report"
	awsscan "github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/scan/aws"
	azurescan "github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/scan/azure"
	gcpscan "github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/scan/gcp"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

type options struct {
	providers   []string
	mock        bool
	output      string
	failOn      bool
	timeout     time.Duration
	includeIPv6 bool
	awsRegions  string
	awsScope    string
	awsRole     string
	gcpProject  string
	gcpOrg      string
	gcpFolder   string
	gcpPolicies bool
	gcpQuota    string
	azureSub    string
	azureAll    bool
	showVersion bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	var providers string
	fs := flag.NewFlagSet("fwscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&providers, "providers", "aws,gcp,azure", "comma separated providers to scan")
	fs.BoolVar(&o.mock, "mock", false, "use built-in fixture data, no credentials or network")
	fs.StringVar(&o.output, "output", "-", "output file, or - for stdout")
	fs.BoolVar(&o.failOn, "fail-on-findings", false, "exit 1 when insecure rules are found")
	fs.DurationVar(&o.timeout, "timeout", 60*time.Second, "overall scan timeout")
	fs.BoolVar(&o.includeIPv6, "include-ipv6", false, "also report ::/0 sources")
	fs.StringVar(&o.awsRegions, "aws-regions", "all", "AWS regions, comma separated, or all")
	fs.StringVar(&o.awsScope, "aws-scope", "auto", "auto, org or account: auto scans the organization when the caller can list its accounts, else the current account")
	fs.StringVar(&o.awsRole, "aws-role-name", "fwscan-reader", "role assumed in the other accounts of an organization")
	fs.StringVar(&o.gcpProject, "gcp-project", "", "GCP project ids, comma separated")
	fs.StringVar(&o.gcpOrg, "gcp-org", "", "GCP organization number, scans every project under it")
	fs.StringVar(&o.gcpFolder, "gcp-folder", "", "GCP folder number, scans every project under it")
	fs.StringVar(&o.gcpQuota, "gcp-quota-project", "", "GCP project billed for API calls, needed for --gcp-org and --gcp-folder with user credentials")
	fs.BoolVar(&o.gcpPolicies, "gcp-policies", true, "also read GCP network and hierarchical firewall policies")
	fs.StringVar(&o.azureSub, "azure-subscription", "", "Azure subscription ids, comma separated")
	fs.BoolVar(&o.azureAll, "azure-all-subscriptions", false, "also scan every enabled Azure subscription the credential can read")
	fs.BoolVar(&o.showVersion, "version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if o.timeout <= 0 {
		return o, errors.New("--timeout must be positive")
	}
	seen := map[string]bool{}
	for _, p := range strings.Split(providers, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		switch p {
		case "":
		case "aws", "gcp", "azure":
			if !seen[p] {
				seen[p] = true
				o.providers = append(o.providers, p)
			}
		default:
			return o, fmt.Errorf("unknown provider %q", p)
		}
	}
	if len(o.providers) == 0 {
		return o, errors.New("no providers selected")
	}
	return o, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, defaultScanners)
}

// runWith is run with replaceable scanners, so tests can drive exit codes and the timeout.
func runWith(args []string, stdout, stderr io.Writer, sc scanners) int {
	o, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fwscan:", err)
		return exitError
	}
	if o.showVersion {
		_, _ = fmt.Fprintln(stdout, "fwscan", version)
		return exitOK
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	rep := scanAll(ctx, o, sc)

	if err := writeOutput(o.output, stdout, rep); err != nil {
		_, _ = fmt.Fprintln(stderr, "fwscan:", err)
		return exitError
	}
	for _, e := range rep.Errors {
		_, _ = fmt.Fprintf(stderr, "fwscan: %s: %s\n", e.Provider, e.Error)
	}
	switch {
	case len(rep.Errors) > 0:
		return exitError
	case o.failOn && rep.FindingCount() > 0:
		return exitFindings
	}
	return exitOK
}

func writeOutput(path string, stdout io.Writer, rep model.Report) error {
	if path == "-" {
		return report.Write(stdout, rep)
	}
	var buf strings.Builder
	if err := report.Write(&buf, rep); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(buf.String()), 0o600)
}

// scanAll runs the selected providers concurrently. A provider failure is
// recorded in the report and never cancels the other providers.
// scanners holds one scan function per provider so tests can replace them.
type scanners struct {
	aws   func(context.Context, options) ([]model.SecurityGroup, error)
	gcp   func(context.Context, options) ([]model.FirewallRule, error)
	azure func(context.Context, options) ([]model.NSG, error)
}

var defaultScanners = scanners{aws: scanAWS, gcp: scanGCP, azure: scanAzure}

func scanAll(ctx context.Context, o options, sc scanners) model.Report {
	rep := model.Report{Errors: []model.ProviderError{}}
	var awsErr, gcpErr, azureErr error
	var g errgroup.Group // no shared context: one failure must not cancel the others
	for _, p := range o.providers {
		switch p {
		case "aws":
			rep.AWS = &model.AWS{SecurityGroups: []model.SecurityGroup{}}
			g.Go(func() error {
				var r []model.SecurityGroup
				r, awsErr = sc.aws(ctx, o)
				rep.AWS.SecurityGroups = append(rep.AWS.SecurityGroups, r...)
				return nil
			})
		case "gcp":
			rep.GCP = &model.GCP{FirewallRules: []model.FirewallRule{}}
			g.Go(func() error {
				var r []model.FirewallRule
				r, gcpErr = sc.gcp(ctx, o)
				rep.GCP.FirewallRules = append(rep.GCP.FirewallRules, r...)
				return nil
			})
		case "azure":
			rep.Azure = &model.Azure{NSGs: []model.NSG{}}
			g.Go(func() error {
				var r []model.NSG
				r, azureErr = sc.azure(ctx, o)
				rep.Azure.NSGs = append(rep.Azure.NSGs, r...)
				return nil
			})
		}
	}
	_ = g.Wait() // goroutines only write their own variables
	for _, pe := range []struct {
		name string
		err  error
	}{{"aws", awsErr}, {"gcp", gcpErr}, {"azure", azureErr}} {
		if pe.err != nil {
			rep.Errors = append(rep.Errors, model.ProviderError{Provider: pe.name, Error: pe.err.Error()})
		}
	}
	return rep
}

func scanAWS(ctx context.Context, o options) ([]model.SecurityGroup, error) {
	if o.mock {
		s := &awsscan.Scanner{Factory: mock.AWSFactory(), DefaultRegion: "us-east-1", IncludeIPv6: o.includeIPv6}
		return s.Scan(ctx)
	}
	s, err := awsscan.New(ctx, awsscan.Options{
		Regions:     o.awsRegions,
		IncludeIPv6: o.includeIPv6,
		Scope:       o.awsScope,
		RoleName:    strings.TrimSpace(o.awsRole),
	})
	if err != nil {
		return nil, err
	}
	return s.Scan(ctx)
}

func scanGCP(ctx context.Context, o options) ([]model.FirewallRule, error) {
	if o.mock {
		s := &gcpscan.Scanner{Lister: mock.GCPLister(), Projects: []string{mock.Project}, IncludeIPv6: o.includeIPv6}
		return s.Scan(ctx)
	}
	s, closeFn, err := gcpscan.New(ctx, gcpscan.Options{
		Projects:     splitList(o.gcpProject),
		Org:          strings.TrimSpace(o.gcpOrg),
		Folder:       strings.TrimSpace(o.gcpFolder),
		Policies:     o.gcpPolicies,
		QuotaProject: strings.TrimSpace(o.gcpQuota),
		IncludeIPv6:  o.includeIPv6,
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeFn() }()
	return s.Scan(ctx)
}

func scanAzure(ctx context.Context, o options) ([]model.NSG, error) {
	if o.mock {
		s := &azurescan.Scanner{Client: mock.AzureClient(), IncludeIPv6: o.includeIPv6}
		return s.Scan(ctx)
	}
	s, err := azurescan.NewMulti(splitList(o.azureSub), o.azureAll, o.includeIPv6)
	if err != nil {
		return nil, err
	}
	return s.Scan(ctx)
}

// splitList splits a comma separated flag value and drops empty entries.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
