package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	// Import from your existing module
	"aws-iam-enumerator/pkg/awsconfig"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const BaseLabel = "myAws"

func main() {
	var (
		region  = flag.String("region", "us-east-1", "AWS region")
		profile = flag.String("profile", "", "AWS profile name")
	)
	flag.Parse()

	ctx := context.Background()

	// Use your config package from the existing module
	awsConfig, err := awsconfig.New(ctx, awsconfig.Options{
		Region:  *region,
		Profile: *profile,
	})
	if err != nil {
		log.Fatalf("Failed to create AWS config: %v", err)
	}

	fmt.Printf("✓ AWS Config created for region: %s\n", awsConfig.GetRegion())

	stsClient := sts.NewFromConfig(awsConfig.GetConfig())

	// Test credentials
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalf("Credential test failed: %v", err)
	}
	fmt.Printf("✓ Authenticated as: %s\n", *identity.Arn)
	fmt.Printf("✓ Account ID: %s\n", *identity.Account)

	if err := handleIAM(ctx, *awsConfig); err != nil {
		log.Fatalf("Iam failed: %v", err)
	}

}
