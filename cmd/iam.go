package main

import (
	"aws-iam-enumerator/pkg/awsconfig"
	cfg "aws-iam-enumerator/pkg/config"
	customIam "aws-iam-enumerator/pkg/iam"
	"context"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/iam"

	com "aws-iam-enumerator/pkg/common"
)

func Use(vals ...any) {
	for _, val := range vals {
		_ = val
	}
}

func handleIAM(ctx context.Context, awsConfig awsconfig.AWSConfig) error {
	// Create IAM client
	graph := com.OpenGraphFormat{Metadata: struct {
		Sourcekind string "json:\"source_kind\""
	}{cfg.BaseLabel}, Graph: struct {
		Nodes []com.Node "json:\"nodes\""
		Edges []com.Edge "json:\"edges\""
	}{
		Nodes: []com.Node{},
		Edges: []com.Edge{},
	}}

	iamClient := iam.NewFromConfig(awsConfig.GetConfig())

	myIamClient := customIam.NewIAMService(iamClient)

	// policies, policiesVersionEdge := myIamClient.ListPolicies(ctx)
	users, userDetails := myIamClient.ListUsers(ctx)
	roles, assumeRolePolicyEdges, roleDetails := myIamClient.ListRoles(ctx)
	// Use(roles, assumeRolePolicyEdges, roleDetails, graph)
	userPermissionsNodes, userPermissionsEdges := myIamClient.GetUsersPermissions(ctx, userDetails)
	rolePermissionsNodes, rolePermissionsEdges := myIamClient.GetRolesPermissions(ctx, roleDetails)

	graph.Graph.Nodes = slices.Concat(graph.Graph.Nodes, users, roles, userPermissionsNodes, rolePermissionsNodes)
	graph.Graph.Edges = slices.Concat(graph.Graph.Edges, userPermissionsEdges, rolePermissionsEdges, assumeRolePolicyEdges)
	com.WriteToFile(graph, "C:\\Users\\Bob\\Desktop\\dev\\aws-enumerator\\bobber.json")

	return nil
}
