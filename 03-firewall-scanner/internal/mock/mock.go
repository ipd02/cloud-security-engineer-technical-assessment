// Package mock provides fixture clients for --mock. They return SDK types, so
// a mock run goes through the real adapter and detection code.
package mock

import (
	"context"

	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	awsscan "github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/scan/aws"
	gcpscan "github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/scan/gcp"
)

// Project is the GCP project name used in mock output.
const Project = "example-project"

// AWSFactory returns a fake EC2 client factory.
func AWSFactory() awsscan.ClientFactory {
	return func(string) awsscan.EC2API { return ec2Client{} }
}

type ec2Client struct{}

func (ec2Client) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	return &ec2.DescribeRegionsOutput{Regions: []ec2types.Region{{RegionName: aws.String("us-east-1")}}}, nil
}

func (ec2Client) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	open := []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{
		{
			GroupId:   aws.String("sg-12345678"),
			GroupName: aws.String("open-sg"),
			IpPermissions: []ec2types.IpPermission{
				{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(8080), ToPort: aws.Int32(8080), IpRanges: open},
				{IpProtocol: aws.String("udp"), FromPort: aws.Int32(123), ToPort: aws.Int32(123), IpRanges: open},
				{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22),
					IpRanges: []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}}},
			},
		},
		{
			GroupId:   aws.String("sg-87654321"),
			GroupName: aws.String("private-sg"),
			IpPermissions: []ec2types.IpPermission{
				{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443),
					IpRanges: []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/16")}}},
			},
		},
	}}, nil
}

// GCPLister returns a fake firewall lister.
func GCPLister() gcpscan.Lister { return lister{} }

type lister struct{}

func (lister) ListFirewalls(context.Context, string) ([]*computepb.Firewall, error) {
	net := "https://www.googleapis.com/compute/v1/projects/" + Project + "/global/networks/default"
	return []*computepb.Firewall{
		{
			Name:         aws.String("allow-all"),
			Network:      aws.String(net),
			Direction:    aws.String("INGRESS"),
			SourceRanges: []string{"0.0.0.0/0"},
			Allowed:      []*computepb.Allowed{{IPProtocol: aws.String("icmp")}},
		},
		{
			Name:         aws.String("disabled-open"),
			Network:      aws.String(net),
			Direction:    aws.String("INGRESS"),
			Disabled:     aws.Bool(true),
			SourceRanges: []string{"0.0.0.0/0"},
			Allowed:      []*computepb.Allowed{{IPProtocol: aws.String("tcp"), Ports: []string{"22"}}},
		},
		{
			Name:         aws.String("internal-only"),
			Network:      aws.String(net),
			Direction:    aws.String("INGRESS"),
			SourceRanges: []string{"10.128.0.0/9"},
			Allowed:      []*computepb.Allowed{{IPProtocol: aws.String("tcp"), Ports: []string{"0-65535"}}},
		},
	}, nil
}

// AzureClient returns a fake NSG client.
func AzureClient() *NSGClient { return &NSGClient{} }

// NSGClient is a fake Azure NSG client with one page of data.
type NSGClient struct{}

// NewListAllPager returns a single page of fixture NSGs.
func (*NSGClient) NewListAllPager(*armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse] {
	return runtime.NewPager(runtime.PagingHandler[armnetwork.SecurityGroupsClientListAllResponse]{
		More: func(armnetwork.SecurityGroupsClientListAllResponse) bool { return false },
		Fetcher: func(context.Context, *armnetwork.SecurityGroupsClientListAllResponse) (armnetwork.SecurityGroupsClientListAllResponse, error) {
			return armnetwork.SecurityGroupsClientListAllResponse{
				SecurityGroupListResult: armnetwork.SecurityGroupListResult{Value: nsgs()},
			}, nil
		},
	})
}

func nsgs() []*armnetwork.SecurityGroup {
	allow := armnetwork.SecurityRuleAccessAllow
	deny := armnetwork.SecurityRuleAccessDeny
	in := armnetwork.SecurityRuleDirectionInbound
	anyProto := armnetwork.SecurityRuleProtocolAsterisk
	return []*armnetwork.SecurityGroup{
		{
			ID:       aws.String("/subscriptions/xxxx/resourceGroups/my-rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg"),
			Name:     aws.String("open-nsg"),
			Location: aws.String("westeurope"),
			Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{
				{Name: aws.String("allow-any"), Properties: &armnetwork.SecurityRulePropertiesFormat{
					Direction: &in, Access: &allow, Protocol: &anyProto,
					SourceAddressPrefix: aws.String("0.0.0.0/0"), DestinationPortRange: aws.String("*"),
				}},
				{Name: aws.String("deny-ssh"), Properties: &armnetwork.SecurityRulePropertiesFormat{
					Direction: &in, Access: &deny, Protocol: &anyProto,
					SourceAddressPrefix: aws.String("*"), DestinationPortRange: aws.String("22"),
				}},
			}},
		},
		{
			ID:       aws.String("/subscriptions/xxxx/resourceGroups/my-rg/providers/Microsoft.Network/networkSecurityGroups/closed-nsg"),
			Name:     aws.String("closed-nsg"),
			Location: aws.String("westeurope"),
			Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{
				{Name: aws.String("allow-vnet"), Properties: &armnetwork.SecurityRulePropertiesFormat{
					Direction: &in, Access: &allow, Protocol: &anyProto,
					SourceAddressPrefix: aws.String("VirtualNetwork"), DestinationPortRange: aws.String("*"),
				}},
			}},
		},
	}
}
