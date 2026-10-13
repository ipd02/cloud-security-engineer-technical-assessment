package detect

import (
	"reflect"
	"testing"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

func i32(v int32) *int32 { return &v }

func TestOpenCIDR(t *testing.T) {
	tests := []struct {
		name string
		in   string
		v6   bool
		want string
		ok   bool
	}{
		{"ipv4 open", "0.0.0.0/0", false, "0.0.0.0/0", true},
		{"ipv4 open with spaces", " 0.0.0.0/0 ", false, "0.0.0.0/0", true},
		{"ipv4 half", "0.0.0.0/1", false, "", false},
		{"ipv4 private", "10.0.0.0/8", false, "", false},
		{"ipv4 non zero base with /0", "10.0.0.0/0", false, "", false},
		{"ipv6 open off", "::/0", false, "", false},
		{"ipv6 open on", "::/0", true, "::/0", true},
		{"ipv6 long form", "0:0:0:0:0:0:0:0/0", true, "::/0", true},
		{"ipv6 narrower", "::/1", true, "", false},
		{"garbage", "any", false, "", false},
		{"empty", "", false, "", false},
		{"no prefix", "0.0.0.0", false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := OpenCIDR(tt.in, tt.v6)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("OpenCIDR(%q, %v) = %q, %v; want %q, %v", tt.in, tt.v6, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestOpenAzureSource(t *testing.T) {
	tests := []struct {
		in   string
		v6   bool
		want string
		ok   bool
	}{
		{"*", false, "*", true},
		{"Any", false, "Any", true},
		{"any", false, "Any", true},
		{"Internet", false, "Internet", true},
		{"INTERNET", false, "Internet", true},
		{"0.0.0.0/0", false, "0.0.0.0/0", true},
		{"::/0", false, "", false},
		{"::/0", true, "::/0", true},
		{"VirtualNetwork", false, "", false},
		{"AzureLoadBalancer", false, "", false},
		{"10.0.0.0/8", false, "", false},
		{"", false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := OpenAzureSource(tt.in, tt.v6)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("got %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestProtocolName(t *testing.T) {
	tests := []struct {
		in       string
		keepStar bool
		want     string
	}{
		{"-1", false, "all"}, {"all", false, "all"}, {"", false, "all"},
		{"*", false, "all"}, {"*", true, "*"},
		{"6", false, "tcp"}, {"17", false, "udp"}, {"1", false, "icmp"}, {"58", false, "icmpv6"},
		{"TCP", false, "tcp"}, {"Udp", true, "udp"}, {"esp", false, "esp"}, {"47", false, "47"},
	}
	for _, tt := range tests {
		if got := ProtocolName(tt.in, tt.keepStar); got != tt.want {
			t.Errorf("ProtocolName(%q, %v) = %q; want %q", tt.in, tt.keepStar, got, tt.want)
		}
	}
}

func TestAWSInsecure(t *testing.T) {
	tests := []struct {
		name string
		in   AWSRule
		v6   bool
		want []model.InsecureRule
	}{
		{"tcp single port", AWSRule{Protocol: "tcp", From: i32(8080), To: i32(8080), IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "8080", Source: "0.0.0.0/0"}}},
		{"udp single port", AWSRule{Protocol: "udp", From: i32(123), To: i32(123), IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "udp", Port: "123", Source: "0.0.0.0/0"}}},
		{"tcp range", AWSRule{Protocol: "tcp", From: i32(1000), To: i32(2000), IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "1000-2000", Source: "0.0.0.0/0"}}},
		{"tcp full range is all", AWSRule{Protocol: "tcp", From: i32(0), To: i32(65535), IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "all", Source: "0.0.0.0/0"}}},
		{"protocol -1 has no ports", AWSRule{Protocol: "-1", IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "all", Port: "all", Source: "0.0.0.0/0"}}},
		{"protocol -1 with port fields", AWSRule{Protocol: "-1", From: i32(-1), To: i32(-1), IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "all", Port: "all", Source: "0.0.0.0/0"}}},
		{"icmp all types", AWSRule{Protocol: "icmp", From: i32(-1), To: i32(-1), IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "icmp", Port: "all", Source: "0.0.0.0/0"}}},
		{"icmp echo request", AWSRule{Protocol: "icmp", From: i32(8), To: i32(0), IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "icmp", Port: "type 8 code 0", Source: "0.0.0.0/0"}}},
		{"numeric protocol 6", AWSRule{Protocol: "6", From: i32(22), To: i32(22), IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0"}}},
		{"other protocol number", AWSRule{Protocol: "47", IPv4: []string{"0.0.0.0/0"}}, false,
			[]model.InsecureRule{{Protocol: "47", Port: "all", Source: "0.0.0.0/0"}}},
		{"one open among several", AWSRule{Protocol: "tcp", From: i32(22), To: i32(22),
			IPv4: []string{"10.0.0.0/8", "0.0.0.0/0", "192.168.0.0/16"}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0"}}},
		{"not open", AWSRule{Protocol: "tcp", From: i32(22), To: i32(22), IPv4: []string{"10.0.0.0/8"}}, false, nil},
		{"ipv6 off", AWSRule{Protocol: "tcp", From: i32(22), To: i32(22), IPv6: []string{"::/0"}}, false, nil},
		{"ipv6 on", AWSRule{Protocol: "tcp", From: i32(22), To: i32(22), IPv6: []string{"::/0"}}, true,
			[]model.InsecureRule{{Protocol: "tcp", Port: "22", Source: "::/0"}}},
		{"ipv4 and ipv6 on", AWSRule{Protocol: "tcp", From: i32(80), To: i32(80), IPv4: []string{"0.0.0.0/0"}, IPv6: []string{"::/0"}}, true,
			[]model.InsecureRule{{Protocol: "tcp", Port: "80", Source: "0.0.0.0/0"}, {Protocol: "tcp", Port: "80", Source: "::/0"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AWSInsecure(tt.in, tt.v6); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v; want %+v", got, tt.want)
			}
		})
	}
}

func TestGCPInsecure(t *testing.T) {
	open := []string{"0.0.0.0/0"}
	tests := []struct {
		name string
		in   GCPRule
		v6   bool
		want []model.InsecureRule
	}{
		{"icmp no ports", GCPRule{Direction: "INGRESS", SourceRanges: open, Allowed: []GCPAllowed{{Protocol: "icmp"}}}, false,
			[]model.InsecureRule{{Protocol: "icmp", Port: "all", Source: "0.0.0.0/0"}}},
		{"tcp ports and range", GCPRule{Direction: "INGRESS", SourceRanges: open,
			Allowed: []GCPAllowed{{Protocol: "tcp", Ports: []string{"22", "8000-9000"}}}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0"}, {Protocol: "tcp", Port: "8000-9000", Source: "0.0.0.0/0"}}},
		{"protocol all", GCPRule{Direction: "INGRESS", SourceRanges: open, Allowed: []GCPAllowed{{Protocol: "all"}}}, false,
			[]model.InsecureRule{{Protocol: "all", Port: "all", Source: "0.0.0.0/0"}}},
		{"full range is all", GCPRule{Direction: "INGRESS", SourceRanges: open,
			Allowed: []GCPAllowed{{Protocol: "udp", Ports: []string{"0-65535"}}}}, false,
			[]model.InsecureRule{{Protocol: "udp", Port: "all", Source: "0.0.0.0/0"}}},
		{"degenerate range", GCPRule{Direction: "INGRESS", SourceRanges: open,
			Allowed: []GCPAllowed{{Protocol: "tcp", Ports: []string{"80-80"}}}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "80", Source: "0.0.0.0/0"}}},
		{"empty direction means ingress", GCPRule{SourceRanges: open, Allowed: []GCPAllowed{{Protocol: "tcp", Ports: []string{"22"}}}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0"}}},
		{"disabled", GCPRule{Direction: "INGRESS", Disabled: true, SourceRanges: open, Allowed: []GCPAllowed{{Protocol: "tcp"}}}, false, nil},
		{"egress", GCPRule{Direction: "EGRESS", SourceRanges: open, Allowed: []GCPAllowed{{Protocol: "tcp"}}}, false, nil},
		{"no allowed entries (deny rule)", GCPRule{Direction: "INGRESS", SourceRanges: open}, false, nil},
		{"narrow source", GCPRule{Direction: "INGRESS", SourceRanges: []string{"35.191.0.0/16"}, Allowed: []GCPAllowed{{Protocol: "tcp"}}}, false, nil},
		{"one open among several", GCPRule{Direction: "INGRESS", SourceRanges: []string{"10.0.0.0/8", "0.0.0.0/0"},
			Allowed: []GCPAllowed{{Protocol: "tcp", Ports: []string{"443"}}}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "443", Source: "0.0.0.0/0"}}},
		{"ipv6 off", GCPRule{Direction: "INGRESS", SourceRanges: []string{"::/0"}, Allowed: []GCPAllowed{{Protocol: "tcp"}}}, false, nil},
		{"ipv6 on", GCPRule{Direction: "INGRESS", SourceRanges: []string{"::/0"}, Allowed: []GCPAllowed{{Protocol: "tcp"}}}, true,
			[]model.InsecureRule{{Protocol: "tcp", Port: "all", Source: "::/0"}}},
		{"source tags only", GCPRule{Direction: "INGRESS", Allowed: []GCPAllowed{{Protocol: "tcp"}}}, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GCPInsecure(tt.in, tt.v6); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v; want %+v", got, tt.want)
			}
		})
	}
}

func TestAzureInsecure(t *testing.T) {
	tests := []struct {
		name string
		in   AzureRule
		v6   bool
		want []model.InsecureRule
	}{
		{"star everything", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "*", SourcePrefix: "*", PortRange: "*"}, false,
			[]model.InsecureRule{{Protocol: "*", Port: "*", Source: "*", RuleID: "r"}}},
		{"cidr", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "Tcp", SourcePrefix: "0.0.0.0/0", PortRange: "22"}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0", RuleID: "r"}}},
		{"internet tag", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "Udp", SourcePrefix: "Internet", PortRange: "53"}, false,
			[]model.InsecureRule{{Protocol: "udp", Port: "53", Source: "Internet", RuleID: "r"}}},
		{"Any literal", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "*", SourcePrefix: "Any", PortRange: "*"}, false,
			[]model.InsecureRule{{Protocol: "*", Port: "*", Source: "Any", RuleID: "r"}}},
		{"prefix list with one open entry", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
			SourcePrefixes: []string{"10.0.0.0/8", "0.0.0.0/0"}, PortRange: "443"}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "443", Source: "0.0.0.0/0", RuleID: "r"}}},
		{"port range list", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "Tcp", SourcePrefix: "*",
			PortRanges: []string{"80", "8000-8100"}}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "80", Source: "*", RuleID: "r"}, {Protocol: "tcp", Port: "8000-8100", Source: "*", RuleID: "r"}}},
		{"dedupe equal sources", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
			SourcePrefixes: []string{"0.0.0.0/0", "0.0.0.0/0"}, PortRange: "80"}, false,
			[]model.InsecureRule{{Protocol: "tcp", Port: "80", Source: "0.0.0.0/0", RuleID: "r"}}},
		{"no port given means any", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "*", SourcePrefix: "*"}, false,
			[]model.InsecureRule{{Protocol: "*", Port: "*", Source: "*", RuleID: "r"}}},
		{"deny", AzureRule{Name: "r", Direction: "Inbound", Access: "Deny", Protocol: "*", SourcePrefix: "*", PortRange: "*"}, false, nil},
		{"outbound", AzureRule{Name: "r", Direction: "Outbound", Access: "Allow", Protocol: "*", SourcePrefix: "*", PortRange: "*"}, false, nil},
		{"virtual network", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "*", SourcePrefix: "VirtualNetwork", PortRange: "*"}, false, nil},
		{"ipv6 off", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "*", SourcePrefix: "::/0", PortRange: "*"}, false, nil},
		{"ipv6 on", AzureRule{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "*", SourcePrefix: "::/0", PortRange: "*"}, true,
			[]model.InsecureRule{{Protocol: "*", Port: "*", Source: "::/0", RuleID: "r"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AzureInsecure(tt.in, tt.v6); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v; want %+v", got, tt.want)
			}
		})
	}
}

func TestSort(t *testing.T) {
	rules := []model.InsecureRule{
		{Protocol: "udp", Port: "123", Source: "0.0.0.0/0"},
		{Protocol: "tcp", Port: "80", Source: "::/0"},
		{Protocol: "tcp", Port: "80", Source: "0.0.0.0/0"},
		{Protocol: "tcp", Port: "22", Source: "0.0.0.0/0"},
	}
	Sort(rules)
	want := []string{"tcp/22/0.0.0.0/0", "tcp/80/0.0.0.0/0", "tcp/80/::/0", "udp/123/0.0.0.0/0"}
	for i, r := range rules {
		if got := r.Protocol + "/" + r.Port + "/" + r.Source; got != want[i] {
			t.Fatalf("index %d: got %s want %s", i, got, want[i])
		}
	}
}
