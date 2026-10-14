// Package model holds the report types. The JSON shape follows the task's
// example. Fields marked additive are extras that do not change that shape.
package model

// InsecureRule is one inbound allow rule open to the internet.
// Port is always a string: "8080", "1000-2000", "all" or "*".
type InsecureRule struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Source   string `json:"source"`
	// RuleID names the Azure rule or the GCP policy rule priority. Additive,
	// omitted when empty.
	RuleID string `json:"rule_id,omitempty"`
}

// SecurityGroup is an AWS security group with at least one insecure rule.
type SecurityGroup struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Region        string         `json:"region,omitempty"` // additive
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// FirewallRule is a GCP VPC firewall rule with at least one insecure entry.
type FirewallRule struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Project string `json:"project,omitempty"` // additive
	// Type is "network_firewall_policy" or "hierarchical_firewall_policy" for
	// policy rules. Additive, omitted for plain VPC firewall rules.
	Type          string         `json:"type,omitempty"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// Types of GCP firewall resources reported besides VPC firewall rules.
const (
	TypeNetworkPolicy      = "network_firewall_policy"
	TypeHierarchicalPolicy = "hierarchical_firewall_policy"
)

// NSG is an Azure network security group with at least one insecure rule.
type NSG struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Location      string         `json:"location,omitempty"` // additive
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// AWS groups the AWS findings.
type AWS struct {
	SecurityGroups []SecurityGroup `json:"security_groups"`
}

// GCP groups the GCP findings.
type GCP struct {
	FirewallRules []FirewallRule `json:"firewall_rules"`
}

// Azure groups the Azure findings.
type Azure struct {
	NSGs []NSG `json:"nsgs"`
}

// ProviderError records a failed or partial provider scan. Additive.
type ProviderError struct {
	Provider string `json:"provider"`
	Error    string `json:"error"`
}

// Report is the full output. A provider that was not selected is omitted.
// Errors is always present, as an empty list when everything worked.
type Report struct {
	AWS    *AWS            `json:"aws,omitempty"`
	GCP    *GCP            `json:"gcp,omitempty"`
	Azure  *Azure          `json:"azure,omitempty"`
	Errors []ProviderError `json:"errors"`
}

// FindingCount returns the number of insecure rules in the report.
func (r Report) FindingCount() int {
	n := 0
	if r.AWS != nil {
		for _, g := range r.AWS.SecurityGroups {
			n += len(g.InsecureRules)
		}
	}
	if r.GCP != nil {
		for _, f := range r.GCP.FirewallRules {
			n += len(f.InsecureRules)
		}
	}
	if r.Azure != nil {
		for _, g := range r.Azure.NSGs {
			n += len(g.InsecureRules)
		}
	}
	return n
}
