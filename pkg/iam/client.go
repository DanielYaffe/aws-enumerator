package iam

import "github.com/aws/aws-sdk-go-v2/service/iam"

type IAMService struct {
	client *iam.Client
}

func NewIAMService(client *iam.Client) *IAMService {
	return &IAMService{client: client}
}
