// Package detect holds the pure functions that decide whether an inbound
// rule is open to the whole internet. It has no SDK dependency.
package detect

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// Any port values used in the output.
const (
	PortAll  = "all"
	PortStar = "*"
)

// OpenCIDR reports whether cidr covers the whole IPv4 internet (0.0.0.0/0).
// With includeIPv6 it also accepts ::/0. It returns the normalised source.
func OpenCIDR(cidr string, includeIPv6 bool) (string, bool) {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || p.Bits() != 0 {
		return "", false
	}
	p = p.Masked() // 0.0.0.1/0 covers the whole internet too
	a := p.Addr()
	switch {
	case a.Is4() && a.IsUnspecified():
		return "0.0.0.0/0", true
	case a.Is6() && !a.Is4In6() && a.IsUnspecified() && includeIPv6:
		return "::/0", true
	}
	return "", false
}

// OpenAzureSource reports whether an Azure source prefix means "anyone".
// "*", "Any", "Internet" and 0.0.0.0/0 count. Matching ignores case.
// It returns the prefix as written, except CIDRs, which are normalised.
func OpenAzureSource(prefix string, includeIPv6 bool) (string, bool) {
	p := strings.TrimSpace(prefix)
	switch strings.ToLower(p) {
	case "*":
		return "*", true
	case "any":
		return "Any", true
	case "internet":
		return "Internet", true
	}
	return OpenCIDR(p, includeIPv6)
}

// ProtocolName maps IP protocol numbers and vendor spellings to one lower
// case name. "-1", "all", "*" and "any" all become "all" except where the
// caller passes keepStar (Azure keeps "*").
func ProtocolName(p string, keepStar bool) string {
	s := strings.ToLower(strings.TrimSpace(p))
	switch s {
	case "", "-1", "all", "any":
		return "all"
	case "*":
		if keepStar {
			return "*"
		}
		return "all"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	case "58":
		return "icmpv6"
	}
	return s
}

// AWSPort formats an AWS permission port range. A nil from or to, or the
// range 0-65535, means all ports. For ICMP the numbers are type and code,
// and -1 means all.
func AWSPort(protocol string, from, to *int32) string {
	switch protocol {
	case "all":
		return PortAll
	case "icmp", "icmpv6":
		if from == nil || *from == -1 {
			return PortAll
		}
		if to == nil || *to == -1 {
			return fmt.Sprintf("type %d", *from)
		}
		return fmt.Sprintf("type %d code %d", *from, *to)
	case "tcp", "udp":
	default:
		// Other protocol numbers have no ports.
		return PortAll
	}
	if from == nil || to == nil || (*from == 0 && *to == 65535) || *from == -1 {
		return PortAll
	}
	if *from == *to {
		return strconv.Itoa(int(*from))
	}
	return fmt.Sprintf("%d-%d", *from, *to)
}

// AWSRule describes one IP permission with the ranges already extracted.
type AWSRule struct {
	Protocol string // raw IpProtocol
	From, To *int32
	IPv4     []string
	IPv6     []string
}

// AWSInsecure returns one insecure rule for every open range of the permission.
func AWSInsecure(r AWSRule, includeIPv6 bool) []model.InsecureRule {
	proto := ProtocolName(r.Protocol, false)
	port := AWSPort(proto, r.From, r.To)
	var out []model.InsecureRule
	for _, c := range r.IPv4 {
		if src, ok := OpenCIDR(c, includeIPv6); ok {
			out = append(out, model.InsecureRule{Protocol: proto, Port: port, Source: src})
		}
	}
	if includeIPv6 {
		for _, c := range r.IPv6 {
			if src, ok := OpenCIDR(c, includeIPv6); ok {
				out = append(out, model.InsecureRule{Protocol: proto, Port: port, Source: src})
			}
		}
	}
	return out
}

// GCPRule describes a firewall rule without any SDK types.
type GCPRule struct {
	Direction    string // INGRESS or EGRESS, empty means INGRESS
	Disabled     bool
	SourceRanges []string
	Allowed      []GCPAllowed
}

// GCPAllowed is one entry of a rule's allowed list.
type GCPAllowed struct {
	Protocol string
	Ports    []string
}

// GCPInsecure returns insecure entries for an enabled ingress allow rule.
// A rule with no ports in an allowed entry covers all ports.
func GCPInsecure(r GCPRule, includeIPv6 bool) []model.InsecureRule {
	if r.Disabled || (r.Direction != "" && !strings.EqualFold(r.Direction, "INGRESS")) {
		return nil
	}
	var sources []string
	for _, c := range r.SourceRanges {
		if src, ok := OpenCIDR(c, includeIPv6); ok {
			sources = append(sources, src)
		}
	}
	var out []model.InsecureRule
	for _, src := range sources {
		for _, a := range r.Allowed {
			proto := ProtocolName(a.Protocol, false)
			if proto == "all" || len(a.Ports) == 0 {
				out = append(out, model.InsecureRule{Protocol: proto, Port: PortAll, Source: src})
				continue
			}
			for _, p := range a.Ports {
				out = append(out, model.InsecureRule{Protocol: proto, Port: normalisePortRange(p), Source: src})
			}
		}
	}
	return out
}

// GCPPolicyRule describes one rule of a hierarchical or network firewall
// policy. Layer4 lists the protocol and port pairs the rule matches.
type GCPPolicyRule struct {
	Priority    int32
	Direction   string // INGRESS or EGRESS
	Action      string // allow, deny, goto_next, apply_security_profile_group
	Disabled    bool
	SrcIPRanges []string
	Layer4      []GCPAllowed
}

// GCPPolicyInsecure returns insecure entries for an enabled ingress policy
// rule whose action is allow. Other actions never open the rule to the internet.
// The priority is reported as the rule id.
func GCPPolicyInsecure(r GCPPolicyRule, includeIPv6 bool) []model.InsecureRule {
	if !strings.EqualFold(r.Action, "allow") {
		return nil
	}
	rules := GCPInsecure(GCPRule{
		Direction:    r.Direction,
		Disabled:     r.Disabled,
		SourceRanges: r.SrcIPRanges,
		Allowed:      r.Layer4,
	}, includeIPv6)
	for i := range rules {
		rules[i].RuleID = strconv.Itoa(int(r.Priority))
	}
	return rules
}

// AzureRule describes one NSG rule without any SDK types.
type AzureRule struct {
	Name           string
	Direction      string // Inbound or Outbound
	Access         string // Allow or Deny
	Protocol       string // *, Tcp, Udp, Icmp, Esp, Ah
	SourcePrefix   string
	SourcePrefixes []string
	PortRange      string
	PortRanges     []string
}

// AzureInsecure returns insecure entries for an inbound allow rule. It does
// not look at rule priority, so a higher-priority deny is not considered.
func AzureInsecure(r AzureRule, includeIPv6 bool) []model.InsecureRule {
	if !strings.EqualFold(r.Direction, "Inbound") || !strings.EqualFold(r.Access, "Allow") {
		return nil
	}
	var sources []string
	for _, s := range append([]string{r.SourcePrefix}, r.SourcePrefixes...) {
		if src, ok := OpenAzureSource(s, includeIPv6); ok && !contains(sources, src) {
			sources = append(sources, src)
		}
	}
	ports := []string{}
	for _, p := range append([]string{r.PortRange}, r.PortRanges...) {
		if strings.TrimSpace(p) != "" {
			ports = append(ports, strings.TrimSpace(p))
		}
	}
	if len(ports) == 0 {
		ports = []string{PortStar}
	}
	proto := ProtocolName(r.Protocol, true)
	var out []model.InsecureRule
	for _, src := range sources {
		for _, p := range ports {
			out = append(out, model.InsecureRule{Protocol: proto, Port: p, Source: src, RuleID: r.Name})
		}
	}
	return out
}

func normalisePortRange(p string) string {
	p = strings.TrimSpace(p)
	lo, hi, ok := strings.Cut(p, "-")
	if ok && lo == hi {
		return lo
	}
	if p == "0-65535" {
		return PortAll
	}
	return p
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Sort orders rules by protocol, port, source and rule id, in place.
func Sort(rules []model.InsecureRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.RuleID < b.RuleID
	})
}
