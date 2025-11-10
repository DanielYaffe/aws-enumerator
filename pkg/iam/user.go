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

func (c *IAMService) ListUsers(ctx context.Context) ([]com.Node, []com.UserDetails) {
	input := &iam.ListUsersInput{
		MaxItems: aws.Int32(500),
	}

	userData, err := c.client.ListUsers(ctx, input)
	if err != nil {
		log.Fatalf("List Users failed: %v", err)
	}
	input.Marker = userData.Marker
	flag := userData.IsTruncated
	users := userData.Users
	for flag {
		userData, err := c.client.ListUsers(ctx, input)
		if err != nil {
			log.Fatalf("List Users failed: %v", err)
		}
		input.Marker = userData.Marker
		flag = userData.IsTruncated
		users = append(users, userData.Users...)

	}
	formattedUsers := []com.Node{}
	userList := []com.UserDetails{}

	for _, user := range users {
		data := com.StructToMap(user)
		formattedUser := com.Node{
			Id:         *user.Arn,
			Kinds:      []string{"AwsUser"},
			Properties: data,
		}

		userList = append(userList, com.UserDetails{Username: *user.UserName, Arn: *user.Arn})

		formattedUsers = append(formattedUsers, formattedUser)
	}
	return formattedUsers, userList
}

func (c *IAMService) GetUsersAttachedPolicies(ctx context.Context, userList []com.UserDetails) []com.Edge {
	allFormattedPolicies := []com.Edge{}
	for _, user := range userList {
		userAttachedPolicy := c.getUserAttachedPolicies(ctx, user)
		allFormattedPolicies = append(allFormattedPolicies, userAttachedPolicy...)
	}
	return allFormattedPolicies
}

func (c *IAMService) GetUsersInlinePolicies(ctx context.Context, userList []com.UserDetails) ([]com.Node, []com.Edge) {
	allNodes := []com.Node{}
	allEdges := []com.Edge{}
	for _, user := range userList {
		userInlinePolicies := c.ListUserInlinePolicies(ctx, user)
		nodes, edges := c.GetUserInlinePolicies(ctx, user, userInlinePolicies)
		allNodes = append(allNodes, nodes...)
		allEdges = append(allEdges, edges...)
	}
	return allNodes, allEdges
}

func (c *IAMService) getUserAttachedPolicies(ctx context.Context, user com.UserDetails) []com.Edge {
	input := &iam.ListAttachedUserPoliciesInput{
		MaxItems: aws.Int32(500),
		UserName: &user.Username,
	}

	policyData, err := c.client.ListAttachedUserPolicies(ctx, input)
	if err != nil {
		log.Fatalf("List policies failed: %v", err)
	}
	input.Marker = policyData.Marker
	flag := policyData.IsTruncated
	policies := policyData.AttachedPolicies
	for flag {
		policyData, err := c.client.ListAttachedUserPolicies(ctx, input)
		if err != nil {
			log.Fatalf("List policies failed: %v", err)
		}
		input.Marker = policyData.Marker
		flag = policyData.IsTruncated
		policies = append(policies, policyData.AttachedPolicies...)

	}
	formattedPolicies := []com.Edge{}

	for _, policy := range policies {
		formattedPolicy := com.Edge{
			Start: com.EdgeQuery{Value: user.Arn, Kind: cfg.BaseLabel},
			End:   com.EdgeQuery{Value: *policy.PolicyArn, Kind: cfg.BaseLabel},
			Kind:  "ATTACHED_POLICY",
		}

		formattedPolicies = append(formattedPolicies, formattedPolicy)
	}
	return formattedPolicies
}

func (c *IAMService) ListUserInlinePolicies(ctx context.Context, user com.UserDetails) []string {
	input := &iam.ListUserPoliciesInput{
		MaxItems: aws.Int32(500),
		UserName: &user.Username,
	}

	policyData, err := c.client.ListUserPolicies(ctx, input)
	if err != nil {
		log.Fatalf("List policies failed: %v", err)
	}
	input.Marker = policyData.Marker
	flag := policyData.IsTruncated
	policies := policyData.PolicyNames
	for flag {
		policyData, err := c.client.ListUserPolicies(ctx, input)
		if err != nil {
			log.Fatalf("List policies failed: %v", err)
		}
		input.Marker = policyData.Marker
		flag = policyData.IsTruncated
		policies = append(policies, policyData.PolicyNames...)

	}

	return policies
}

func (c *IAMService) GetUserInlinePolicies(ctx context.Context, user com.UserDetails, policyNames []string) ([]com.Node, []com.Edge) {
	allNodes := []com.Node{}
	allEdges := []com.Edge{}
	for _, policy := range policyNames {
		input := &iam.GetUserPolicyInput{
			UserName:   &user.Username,
			PolicyName: aws.String(policy),
		}

		policyData, err := c.client.GetUserPolicy(ctx, input)
		if err != nil {
			log.Fatalf("List policies failed: %v", err)
		}

		nodes, edges := c.GetInlinePolicies(ctx, policyData.PolicyDocument, policy, user.Arn)
		allNodes = append(allNodes, nodes...)
		allEdges = append(edges, edges...)

	}
	return allNodes, allEdges
}

func (c *IAMService) GetUsersPermissions(ctx context.Context, userDetails []com.UserDetails) ([]com.Node, []com.Edge) {
	allNodes := []com.Node{}
	allEdges := []com.Edge{}
	inlineNodes, inlineEdges := c.GetUsersInlinePolicies(ctx, userDetails)
	attachedEdges := c.GetUsersAttachedPolicies(ctx, userDetails)
	allNodes = append(allNodes, inlineNodes...)
	allEdges = slices.Concat(allEdges, inlineEdges, attachedEdges)

	return allNodes, allEdges
}
