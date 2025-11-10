package awsconfig

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// AWSConfig provides AWS configuration management
type AWSConfig struct {
	config aws.Config
}

// Options represents AWS configuration options
type Options struct {
	Profile         string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// New creates a new AWS configuration
func New(ctx context.Context, opts Options) (*AWSConfig, error) {
	var awsConfig aws.Config
	var err error

	// Set default region if not provided
	if opts.Region == "" {
		opts.Region = "us-east-1"
	}

	// Configure based on provided options
	if opts.AccessKeyID != "" && opts.SecretAccessKey != "" {
		// Use explicit credentials
		awsConfig, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(opts.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				opts.AccessKeyID,
				opts.SecretAccessKey,
				opts.SessionToken,
			)),
		)
	} else if opts.Profile != "" {
		// Use named profile
		awsConfig, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(opts.Region),
			config.WithSharedConfigProfile(opts.Profile),
		)
	} else {
		// Use default credential chain
		awsConfig, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(opts.Region),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSConfig{
		config: awsConfig,
	}, nil
}

// GetConfig returns the underlying aws.Config for creating clients
func (c *AWSConfig) GetConfig() aws.Config {
	return c.config
}

// GetRegion returns the configured region
func (c *AWSConfig) GetRegion() string {
	return c.config.Region
}
