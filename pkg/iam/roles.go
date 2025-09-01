package iam

import (
	com "aws-iam-enumerator/pkg/common"
	cfg "aws-iam-enumerator/pkg/config"
	"context"
	"log"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func (c *IAMService) ListRoles(ctx context.Context) ([]com.Node, []com.RoleDetails) {
	input := &iam.ListRolesInput{
		MaxItems: aws.Int32(500),
	}

	roleData, err := c.client.ListRoles(ctx, input)
	if err != nil {
		log.Fatalf("List roles failed: %v", err)
	}
	input.Marker = roleData.Marker
	flag := roleData.IsTruncated
	roles := roleData.Roles
	for flag {
		roleData, err := c.client.ListRoles(ctx, input)
		if err != nil {
			log.Fatalf("List policies failed: %v", err)
		}
		input.Marker = roleData.Marker
		flag = roleData.IsTruncated
		roles = append(roles, roleData.Roles...)

	}
	nodes := []com.Node{}
	roleDetails := []com.RoleDetails{}

	for _, role := range roles {
		data, err := com.StructToMap(role)
		if err != nil {
			log.Fatalf("failed to convert struct to json: %v", err)
		}

		roleNode := com.Node{
			Id:         *role.Arn,
			Kinds:      []string{"Policy"},
			Properties: data,
		}
		roleDetails = append(roleDetails, com.RoleDetails{
			RoleName: *role.RoleName,
			Arn:      *role.Arn,
		})
		nodes = append(nodes, roleNode)
	}
	return nodes, roleDetails
}

func (c *IAMService) GetRolesAttachedPolicies(ctx context.Context, rolesDetails []com.RoleDetails) []com.Edge {
	allFormattedRolesPolicies := []com.Edge{}
	for _, role := range rolesDetails {
		roleAttachedPolicy := c.GetRoleAttachedPolicies(ctx, role)
		allFormattedRolesPolicies = append(allFormattedRolesPolicies, roleAttachedPolicy...)
	}
	return allFormattedRolesPolicies
}
func (c *IAMService) GetRoleAttachedPolicies(ctx context.Context, roleDetails com.RoleDetails) []com.Edge {
	edges := []com.Edge{}

	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleDetails.RoleName,
	}
	roleAttachedPolicies, err := c.client.ListAttachedRolePolicies(ctx, input)
	if err != nil {
		log.Fatalf("List role attached policies failed: %v", err)
	}

	for _, rolePolicy := range roleAttachedPolicies.AttachedPolicies {
		formattedRole := com.Edge{
			Start: com.EdgeQuery{Value: roleDetails.Arn, Kind: cfg.BaseLabel},
			End:   com.EdgeQuery{Value: *rolePolicy.PolicyArn, Kind: cfg.BaseLabel},
		}
		edges = append(edges, formattedRole)
	}
	return edges
}

func (c *IAMService) ListRoleInlinePolicies(ctx context.Context, roleDetails com.RoleDetails) []string {
	input := &iam.ListRolePoliciesInput{
		MaxItems: aws.Int32(500),
		RoleName: &roleDetails.RoleName,
	}

	policyData, err := c.client.ListRolePolicies(ctx, input)
	if err != nil {
		log.Fatalf("List policies failed: %v", err)
	}
	input.Marker = policyData.Marker
	flag := policyData.IsTruncated
	policies := policyData.PolicyNames
	for flag {
		policyData, err := c.client.ListRolePolicies(ctx, input)
		if err != nil {
			log.Fatalf("List policies failed: %v", err)
		}
		input.Marker = policyData.Marker
		flag = policyData.IsTruncated
		policies = append(policies, policyData.PolicyNames...)

	}

	return policies
}

func (c *IAMService) GetRoleInlinePolicies(ctx context.Context, role com.RoleDetails, policyNames []string) ([]com.Node, []com.Edge) {
	formattedPolicies := []com.Node{}
	edges := []com.Edge{}
	for _, policy := range policyNames {
		input := &iam.GetRolePolicyInput{
			RoleName:   &role.RoleName,
			PolicyName: aws.String(policy),
		}

		policyData, err := c.client.GetRolePolicy(ctx, input)
		if err != nil {
			log.Fatalf("List policies failed: %v", err)
		}

		data, err := com.StructToMap(policyData)
		if err != nil {
			log.Fatalf("failed to convert struct to json: %v", err)
		}

		formattedPolicy := com.Node{
			Id:         role.Arn + "-" + *policyData.PolicyName,
			Kinds:      []string{"Policy"},
			Properties: data,
		}

		policyEdge := com.Edge{
			Start: com.EdgeQuery{Value: role.Arn, Kind: cfg.BaseLabel},
			End:   com.EdgeQuery{Value: role.Arn + "-" + *policyData.PolicyName, Kind: cfg.BaseLabel},
			Kind:  "RoleInlinePolicy",
		}

		formattedPolicies = append(formattedPolicies, formattedPolicy)
		edges = append(edges, policyEdge)
	}
	return formattedPolicies, edges

}

func (c *IAMService) GetRolesInlinePolicies(ctx context.Context, roleDetails []com.RoleDetails) ([]com.Node, []com.Edge) {
	allNodes := []com.Node{}
	allEdges := []com.Edge{}
	for _, role := range roleDetails {
		roleInlinePolicies := c.ListRoleInlinePolicies(ctx, role)
		nodes, edges := c.GetRoleInlinePolicies(ctx, role, roleInlinePolicies)
		allNodes = append(allNodes, nodes...)
		allEdges = append(allEdges, edges...)
	}
	return allNodes, allEdges
}

func (c *IAMService) GetRolesPermissions(ctx context.Context, roleDetails []com.RoleDetails) ([]com.Node, []com.Edge) {
	allNodes := []com.Node{}
	allEdges := []com.Edge{}
	inlineNodes, inlineEdges := c.GetRolesInlinePolicies(ctx, roleDetails)
	attachedEdges := c.GetRolesAttachedPolicies(ctx, roleDetails)
	allNodes = append(allNodes, inlineNodes...)
	allEdges = slices.Concat(allEdges, inlineEdges, attachedEdges)

	return allNodes, allEdges
}
