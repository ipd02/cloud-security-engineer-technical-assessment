package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestMockGolden(t *testing.T) {
	code, out, _ := runArgs(t, "--mock")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	golden := filepath.Join("testdata", "mock.golden.json")
	if *update {
		if err := os.WriteFile(golden, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := fs.ReadFile(os.DirFS("testdata"), "mock.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Fatalf("output differs from %s (run go test -update to refresh)\n got:\n%s", golden, out)
	}
	// Every port is a string and the output is valid JSON.
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
}

func TestMockIsStable(t *testing.T) {
	_, a, _ := runArgs(t, "--mock")
	for range 5 {
		if _, b, _ := runArgs(t, "--mock"); a != b {
			t.Fatal("output changed between runs")
		}
	}
}

func TestMockProviderSelection(t *testing.T) {
	code, out, _ := runArgs(t, "--mock", "--providers", "gcp")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, `"aws"`) || strings.Contains(out, `"azure"`) || !strings.Contains(out, `"gcp"`) {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"mock without fail flag", []string{"--mock"}, exitOK},
		{"mock with fail flag", []string{"--mock", "--fail-on-findings"}, exitFindings},
		{"version", []string{"--version"}, exitOK},
		{"unknown flag", []string{"--nope"}, exitError},
		{"unknown provider", []string{"--providers", "oci"}, exitError},
		{"empty providers", []string{"--providers", ","}, exitError},
		{"bad timeout", []string{"--timeout", "0s"}, exitError},
		{"stray argument", []string{"extra"}, exitError},
		{"gcp org and folder together", []string{"--providers", "gcp", "--gcp-org", "1", "--gcp-folder", "2"}, exitError},
		{"unwritable output", []string{"--mock", "--output", filepath.Join(t.TempDir(), "no", "such", "dir", "o.json")}, exitError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code, _, _ := runArgs(t, tt.args...); code != tt.want {
				t.Fatalf("exit = %d; want %d", code, tt.want)
			}
		})
	}
}

// A provider that fails is named in the errors field and on stderr. The scanners
// are fakes: a real scan would use the credentials of the machine.
func TestProviderErrorIsInErrorsField(t *testing.T) {
	var out, errb bytes.Buffer
	code := runWith([]string{"--providers", "gcp"}, &out, &errb, scanners{gcp: failingGCP})
	if code != exitError {
		t.Fatalf("exit = %d", code)
	}
	var rep model.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Provider != "gcp" || !strings.Contains(errb.String(), "gcp: permission denied") {
		t.Fatalf("errors = %+v, stderr = %q", rep.Errors, errb.String())
	}
}

func TestVersion(t *testing.T) {
	old := version
	version = "v1.2.3"
	defer func() { version = old }()
	_, out, _ := runArgs(t, "--version")
	if strings.TrimSpace(out) != "fwscan v1.2.3" {
		t.Fatalf("got %q", out)
	}
}

func TestOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	code, stdout, _ := runArgs(t, "--mock", "--output", path)
	if code != exitOK || stdout != "" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	b, err := fs.ReadFile(os.DirFS(filepath.Dir(path)), filepath.Base(path))
	if err != nil || !strings.Contains(string(b), "sg-12345678") {
		t.Fatalf("file: %v %q", err, b)
	}
}

// One failing provider must not hide the others.
func TestProviderFailureIsIsolated(t *testing.T) {
	sc := scanners{
		aws: func(context.Context, options) ([]model.SecurityGroup, error) {
			return []model.SecurityGroup{{ID: "sg-1", Name: "n", InsecureRules: []model.InsecureRule{{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0"}}}}, nil
		},
		gcp: func(context.Context, options) ([]model.FirewallRule, error) {
			return nil, errors.New("permission denied")
		},
		azure: func(context.Context, options) ([]model.NSG, error) {
			return []model.NSG{{ID: "/n", Name: "n", InsecureRules: []model.InsecureRule{{Protocol: "*", Port: "*", Source: "*"}}}}, nil
		},
	}
	rep := scanAll(context.Background(), options{providers: []string{"aws", "gcp", "azure"}}, sc)
	if len(rep.AWS.SecurityGroups) != 1 || len(rep.Azure.NSGs) != 1 {
		t.Fatalf("results lost: %+v", rep)
	}
	if rep.GCP == nil || rep.GCP.FirewallRules == nil || len(rep.GCP.FirewallRules) != 0 {
		t.Fatalf("gcp should be an empty list: %+v", rep.GCP)
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Provider != "gcp" || rep.Errors[0].Error != "permission denied" {
		t.Fatalf("errors = %+v", rep.Errors)
	}
	if rep.FindingCount() != 2 {
		t.Fatalf("findings = %d", rep.FindingCount())
	}
}

func openAWS(context.Context, options) ([]model.SecurityGroup, error) {
	return []model.SecurityGroup{{ID: "sg-1", Name: "n", InsecureRules: []model.InsecureRule{{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0"}}}}, nil
}

func failingGCP(context.Context, options) ([]model.FirewallRule, error) {
	return nil, errors.New("permission denied")
}

func TestExitCodePrecedence(t *testing.T) {
	tests := []struct {
		name string
		args []string
		sc   scanners
		want int
	}{
		{"findings only", []string{"--providers", "aws", "--fail-on-findings"}, scanners{aws: openAWS}, exitFindings},
		{"findings and a failed provider", []string{"--providers", "aws,gcp", "--fail-on-findings"}, scanners{aws: openAWS, gcp: failingGCP}, exitError},
		{"findings and a failed provider without the flag", []string{"--providers", "aws,gcp"}, scanners{aws: openAWS, gcp: failingGCP}, exitError},
		{"findings without the flag", []string{"--providers", "aws"}, scanners{aws: openAWS}, exitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := runWith(tt.args, &out, &errb, tt.sc); code != tt.want {
				t.Fatalf("exit = %d; want %d", code, tt.want)
			}
		})
	}
}

// The timeout reaches the scanners, and a provider that times out is
// reported while the others still return their results.
func TestTimeoutReachesScanners(t *testing.T) {
	sc := scanners{
		aws: openAWS,
		gcp: func(ctx context.Context, _ options) ([]model.FirewallRule, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	var out, errb bytes.Buffer
	code := runWith([]string{"--providers", "aws,gcp", "--timeout", "50ms"}, &out, &errb, sc)
	if code != exitError {
		t.Fatalf("exit = %d", code)
	}
	var rep model.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Provider != "gcp" || !strings.Contains(rep.Errors[0].Error, "deadline exceeded") {
		t.Fatalf("errors = %+v", rep.Errors)
	}
	if rep.AWS == nil || len(rep.AWS.SecurityGroups) != 1 {
		t.Fatalf("aws result lost: %+v", rep.AWS)
	}
}

// A failing provider must not cancel the context of the others.
func TestFailureDoesNotCancelOthers(t *testing.T) {
	sc := scanners{
		gcp: failingGCP,
		aws: func(ctx context.Context, o options) ([]model.SecurityGroup, error) {
			time.Sleep(50 * time.Millisecond)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return openAWS(ctx, o)
		},
	}
	rep := scanAll(context.Background(), options{providers: []string{"gcp", "aws"}}, sc)
	if len(rep.Errors) != 1 || rep.Errors[0].Provider != "gcp" || len(rep.AWS.SecurityGroups) != 1 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestOutputFileModeAndOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if code, _, _ := runArgs(t, "--mock", "--output", path); code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v; want 0600", st.Mode().Perm())
	}
	if code, _, _ := runArgs(t, "--mock", "--providers", "gcp", "--output", path); code != exitOK {
		t.Fatalf("second run exit = %d", code)
	}
	b, err := fs.ReadFile(os.DirFS(filepath.Dir(path)), filepath.Base(path))
	if err != nil || strings.Contains(string(b), "sg-12345678") {
		t.Fatalf("file not overwritten: %v %q", err, b)
	}
}

func TestFlagDefaults(t *testing.T) {
	o, err := parseFlags(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !o.gcpPolicies || o.includeIPv6 || o.failOn || o.mock {
		t.Fatalf("defaults = %+v", o)
	}
	if got := splitList(" a, b,,c "); len(got) != 3 || got[1] != "b" {
		t.Fatalf("splitList = %v", got)
	}
}
