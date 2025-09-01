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

	policies, policiesVersionEdge := myIamClient.ListPolicies(ctx)
	users, userList := myIamClient.ListUsers(ctx)
	roles, roleDetails := myIamClient.ListRoles(ctx)
	userPermissionsNodes, userPermissionsEdges := myIamClient.GetUsersPermissions(ctx, userList)
	rolePermissionsNodes, rolePermissionsEdges := myIamClient.GetRolesPermissions(ctx, roleDetails)

	graph.Graph.Nodes = slices.Concat(graph.Graph.Nodes, policies, users, roles, userPermissionsNodes, rolePermissionsNodes)
	graph.Graph.Edges = slices.Concat(graph.Graph.Edges, userPermissionsEdges, rolePermissionsEdges, policiesVersionEdge)

	com.WriteToFile(graph, "C:\\Users\\Bob\\Desktop\\dev\\aws-enumerator\\bobber.json")

	return nil
}
