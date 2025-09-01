package iam

import (
	com "aws-iam-enumerator/pkg/common"
	cfg "aws-iam-enumerator/pkg/config"
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func (c *IAMService) ListPolicies(ctx context.Context) ([]com.Node, []com.Edge) {
	edges := []com.Edge{}
	input := &iam.ListPoliciesInput{
		MaxItems: aws.Int32(500),
	}

	policyData, err := c.client.ListPolicies(ctx, input)
	if err != nil {
		log.Fatalf("List policies failed: %v", err)
	}
	input.Marker = policyData.Marker
	flag := policyData.IsTruncated
	policies := policyData.Policies
	for flag {
		policyData, err := c.client.ListPolicies(ctx, input)
		if err != nil {
			log.Fatalf("List policies failed: %v", err)
		}
		input.Marker = policyData.Marker
		flag = policyData.IsTruncated
		policies = append(policies, policyData.Policies...)

	}
	formattedPolicies := []com.Node{}

	for _, policy := range policies {
		data, err := com.StructToMap(policy)
		if err != nil {
			log.Fatalf("failed to convert struct to json: %v", err)
		}

		formattedPolicy := com.Node{
			Id:         *policy.Arn,
			Kinds:      []string{"Policy"},
			Properties: data,
		}
		node, edge := c.GetPolicyByArnAndVersion(ctx, *policy.Arn, *policy.DefaultVersionId)
		formattedPolicies = append(formattedPolicies, formattedPolicy, node)
		edges = append(edges, edge)

	}
	return formattedPolicies, edges
}

func (c *IAMService) GetPolicyByArnAndVersion(ctx context.Context, policyArn string, version string) (com.Node, com.Edge) {
	policyData, err := c.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: &policyArn, VersionId: &version})
	if err != nil {
		log.Fatalf("List policies failed: %v", err)
	}

	data, err := com.StructToMap(policyData.PolicyVersion.Document)
	if err != nil {
		log.Fatalf("failed to convert struct to json: %v", err)
	}

	kinds := []string{"PolicyVersion"}
	if policyData.PolicyVersion.IsDefaultVersion {
		kinds = append(kinds, "DefaultVersion")
	}
	return com.Node{
			Id:         policyArn + "-" + version,
			Kinds:      kinds,
			Properties: data,
		}, com.Edge{
			Start: com.EdgeQuery{Value: policyArn, Kind: cfg.BaseLabel},
			End:   com.EdgeQuery{Value: policyArn + "-" + version, Kind: cfg.BaseLabel},
		}
}
