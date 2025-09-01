package main

import (
	"aws-iam-enumerator/pkg/awsconfig"
	customIam "aws-iam-enumerator/pkg/iam"
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func handleS3(ctx context.Context, awsConfig awsconfig.AWSConfig) (bool, error) {
	// Create IAM client
	iamClient := iam.NewFromConfig(awsConfig.GetConfig())

	myIamClient := customIam.NewIAMService(iamClient)

	myIamClient.ListPolicies(ctx)

	return true, nil
}
