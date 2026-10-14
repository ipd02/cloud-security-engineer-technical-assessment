// Package azure lists network security groups and reports inbound allow rules open to the internet.
package azure

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/detect"
	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// NSGAPI is the part of the SecurityGroupsClient that the scanner uses.
type NSGAPI interface {
	NewListAllPager(options *armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse]
}

// Scanner scans one subscription.
type Scanner struct {
	Client      NSGAPI
	IncludeIPv6 bool
}

// NewWithCredential builds a Scanner from a credential and optional client options.
func NewWithCredential(subscription string, cred azcore.TokenCredential, includeIPv6 bool, opts *arm.ClientOptions) (*Scanner, error) {
	c, err := armnetwork.NewSecurityGroupsClient(subscription, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("create azure nsg client: %w", err)
	}
	return &Scanner{Client: c, IncludeIPv6: includeIPv6}, nil
}

// Scan returns NSGs that have insecure custom rules. Default rules are skipped:
// they only allow VirtualNetwork and load balancer sources inbound.
func (s *Scanner) Scan(ctx context.Context) ([]model.NSG, error) {
	pager := s.Client.NewListAllPager(nil)
	var out []model.NSG
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, fmt.Errorf("list network security groups: %w", brief(err))
		}
		for _, nsg := range page.Value {
			if n, ok := convert(nsg, s.IncludeIPv6); ok {
				out = append(out, n)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func convert(nsg *armnetwork.SecurityGroup, includeIPv6 bool) (model.NSG, bool) {
	if nsg == nil || nsg.Properties == nil {
		return model.NSG{}, false
	}
	var rules []model.InsecureRule
	for _, sr := range nsg.Properties.SecurityRules {
		if sr == nil || sr.Properties == nil {
			continue
		}
		p := sr.Properties
		r := detect.AzureRule{
			Name:           str(sr.Name),
			Direction:      enumStr(p.Direction),
			Access:         enumStr(p.Access),
			Protocol:       enumStr(p.Protocol),
			SourcePrefix:   str(p.SourceAddressPrefix),
			SourcePrefixes: strs(p.SourceAddressPrefixes),
			PortRange:      str(p.DestinationPortRange),
			PortRanges:     strs(p.DestinationPortRanges),
		}
		rules = append(rules, detect.AzureInsecure(r, includeIPv6)...)
	}
	if len(rules) == 0 {
		return model.NSG{}, false
	}
	detect.Sort(rules)
	return model.NSG{ID: str(nsg.ID), Name: str(nsg.Name), Location: str(nsg.Location), InsecureRules: rules}, true
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func strs(s []*string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if v != nil {
			out = append(out, *v)
		}
	}
	return out
}

func enumStr[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}

// briefError replaces the SDK's long error text, which holds the request URL,
// the response headers and the whole response body, with the status and code.
type briefError struct {
	msg string
	err error
}

func (e *briefError) Error() string { return e.msg }
func (e *briefError) Unwrap() error { return e.err }

func brief(err error) error {
	var re *azcore.ResponseError
	if !errors.As(err, &re) {
		return err
	}
	msg := fmt.Sprintf("HTTP %d", re.StatusCode)
	if re.ErrorCode != "" {
		msg += " " + re.ErrorCode
	}
	return &briefError{msg: msg, err: err}
}
