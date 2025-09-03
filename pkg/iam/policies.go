package iam

import (
	com "aws-iam-enumerator/pkg/common"
	cfg "aws-iam-enumerator/pkg/config"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// PolicyDocument represents the top-level policy structure
type PolicyDocument struct {
	Version   string     `json:"Version"`
	Statement Statements `json:"Statement"`
}

// Statement represents a policy statement
type Statement struct {
	Effect    string     `json:"Effect"`
	Action    Actions    `json:"Action,omitempty"`
	NotAction Actions    `json:"NotAction,omitempty"`
	Resource  Resource   `json:"Resource,omitempty"`
	Principal Principal  `json:"Principal,omitempty"`
	Condition *Condition `json:"Condition,omitempty"`
}
type ConditionValue []string

func (cv *ConditionValue) UnmarshalJSON(data []byte) error {
	// Try array first
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*cv = arr
		return nil
	}

	// Try single string and convert to array
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*cv = []string{str}
		return nil
	}

	// Try number and convert to string array
	var num float64
	if err := json.Unmarshal(data, &num); err == nil {
		*cv = []string{fmt.Sprintf("%g", num)}
		return nil
	}

	// Try boolean and convert to string array
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*cv = []string{fmt.Sprintf("%t", b)}
		return nil
	}

	return fmt.Errorf("unable to unmarshal condition value")
}

func (cv ConditionValue) MarshalJSON() ([]byte, error) {
	if len(cv) == 1 {
		return json.Marshal(cv[0])
	}
	return json.Marshal([]string(cv))
}

// Condition represents IAM policy conditions
type Condition map[string]map[string]ConditionValue

// Statements handles fields that can be either a single Statement object or []Statement
type Statements []Statement

// UnmarshalJSON implements custom unmarshaling for Statements
func (s *Statements) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as single Statement object first
	var stmt Statement
	if err := json.Unmarshal(data, &stmt); err == nil {
		*s = Statements{stmt} // Convert single statement to array
		return nil
	}

	// If that fails, try as array of statements
	var stmts []Statement
	if err := json.Unmarshal(data, &stmts); err != nil {
		return err
	}
	*s = Statements(stmts)
	return nil
}

// Actions handles fields that can be either string or []string
type Actions []string

// UnmarshalJSON implements custom unmarshaling for Actions
func (a *Actions) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*a = Actions{str} // Convert single string to array
		return nil
	}

	// If that fails, try as array
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = Actions(arr)
	return nil
}

// Resource handles fields that can be either string or []string (same as Actions)
type Resource []string

// UnmarshalJSON implements custom unmarshaling for Resource
func (r *Resource) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*r = Resource{str} // Convert single string to array
		return nil
	}

	// If that fails, try as array
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*r = Resource(arr)
	return nil
}

type Principal struct {
	Value any `json:"-"`
}

type PrincipalDetails struct {
	AWS           PrincipalValue `json:"AWS,omitempty"`
	Service       PrincipalValue `json:"Service,omitempty"`
	Federated     PrincipalValue `json:"Federated,omitempty"`
	CanonicalUser PrincipalValue `json:"CanonicalUser,omitempty"`
}

type PrincipalValue struct {
	Values []string
}

func (p *Principal) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		p.Value = str
		return nil
	}

	var details PrincipalDetails
	if err := json.Unmarshal(data, &details); err != nil {
		return err
	}
	p.Value = details
	return nil
}

func (p Principal) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Value)
}

func (pv *PrincipalValue) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		pv.Values = arr
		return nil
	}

	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	pv.Values = []string{str}
	return nil
}

func (pv PrincipalValue) MarshalJSON() ([]byte, error) {
	if len(pv.Values) == 1 {
		return json.Marshal(pv.Values[0])
	}
	return json.Marshal(pv.Values)
}

// DecodePolicyToStruct decodes URL-encoded policy and unmarshals into struct
func DecodePolicyToStruct(encodedPolicy *string) (*PolicyDocument, error) {
	if encodedPolicy == nil {
		return nil, fmt.Errorf("encoded policy is nil")
	}

	// URL decode the policy document
	decodedPolicy, err := url.QueryUnescape(*encodedPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to URL decode: %w", err)
	}

	// Parse the JSON into our struct
	var policy PolicyDocument
	if err := json.Unmarshal([]byte(decodedPolicy), &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &policy, nil
}

func (c *IAMService) ListPolicies(ctx context.Context) ([]com.Node, []com.Edge) {
	policyEdges := []com.Edge{}
	formattedPolicies := []com.Node{}
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

	for index, policy := range policies {
		if index%100 == 0 {
			fmt.Printf("processed %d policies\n", index)
		}
		formattedPolicy := com.Node{
			Id:         *policy.Arn,
			Kinds:      []string{"Policy"},
			Properties: com.StructToMap(policy),
		}
		nodes, edges := c.GetPolicyByArnAndVersion(ctx, *policy.Arn, *policy.DefaultVersionId)
		formattedPolicies = append(formattedPolicies, formattedPolicy)
		formattedPolicies = append(formattedPolicies, nodes...)
		policyEdges = append(policyEdges, edges...)
	}

	return formattedPolicies, policyEdges
}

func (c *IAMService) GetPolicyByArnAndVersion(ctx context.Context, policyArn string, version string) ([]com.Node, []com.Edge) {
	edges := []com.Edge{}
	nodes := []com.Node{}

	policyData, err := c.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: &policyArn, VersionId: &version})
	if err != nil {
		log.Fatalf("List policies failed: %v", err)
	}

	kinds := []string{"PolicyVersion"}
	if policyData.PolicyVersion.IsDefaultVersion {
		kinds = append(kinds, "DefaultVersion")
	}

	nodes = append(nodes, com.Node{
		Id:         policyArn + "-" + version,
		Kinds:      kinds,
		Properties: map[string]any{"VersionId": version, "IsDefaultVersion": strconv.FormatBool(policyData.PolicyVersion.IsDefaultVersion), "CreateDate": policyData.PolicyVersion.CreateDate},
	})
	edges = append(edges, com.Edge{
		Start: com.EdgeQuery{Value: policyArn, Kind: cfg.BaseLabel},
		End:   com.EdgeQuery{Value: policyArn + "-" + version, Kind: cfg.BaseLabel},
		Kind:  "HAS_VERSION",
	})
	policyNodes, policyEdges := c.DecodePolicyDocument(ctx, policyData.PolicyVersion.Document, policyArn+"-"+version)
	nodes = append(nodes, policyNodes...)
	edges = append(edges, policyEdges...)
	return nodes, edges
}

func (c *IAMService) DecodePolicyDocument(ctx context.Context, policyDocument *string, policyIdentifier string) ([]com.Node, []com.Edge) {
	edges := []com.Edge{}
	nodes := []com.Node{}

	policy, err := DecodePolicyToStruct(policyDocument)
	if err != nil {
		log.Fatalf("decode struct failed: %v", err)
	}
	for index, statement := range policy.Statement {
		properties := map[string]any{"Effect": statement.Effect}
		if statement.Action == nil {
			properties["NotAction"] = statement.NotAction
		} else if statement.NotAction == nil {
			properties["Action"] = statement.Action
		}
		if resource := statement.Resource; len(resource) > 0 {
			properties["Resources"] = resource
		}
		// Type assert to check what type it is
		if str, ok := statement.Principal.Value.(string); ok {
			properties["awsPrincipals"] = []string{str}
		} else if details, ok := statement.Principal.Value.(PrincipalDetails); ok {
			// Access the fields
			if aws := details.AWS.Values; len(aws) > 0 {
				properties["awsPrincipals"] = aws
			}
			if svc := details.Service.Values; len(svc) > 0 {
				properties["servicePrincipals"] = svc
			}
			if fed := details.Federated.Values; len(fed) > 0 {
				properties["federatedPrincipals"] = fed
			}
			if can := details.CanonicalUser.Values; len(can) > 0 {
				properties["canonicalUserPrincipals"] = can
			}
		}

		nodes = append(nodes, com.Node{
			Id:         policyIdentifier + "-stmt-" + fmt.Sprint(index),
			Kinds:      []string{"Statement"},
			Properties: properties,
		})
		edges = append(edges, com.Edge{
			Start: com.EdgeQuery{Value: policyIdentifier, Kind: cfg.BaseLabel},
			End:   com.EdgeQuery{Value: policyIdentifier + "-stmt-" + fmt.Sprint(index), Kind: cfg.BaseLabel},
			Kind:  "CONTAINS_STATEMENT",
		})
		for operator, conditionMap := range *statement.Condition {
			for key, conditionValue := range conditionMap {
				for _, value := range conditionValue {
					nodes = append(nodes, com.Node{
						Id:    policyIdentifier + "-stmt-" + fmt.Sprint(index) + "-" + operator + "-" + key + "-" + value,
						Kinds: []string{"Condition"},
						Properties: map[string]any{
							"operator": operator,
							"key":      key,
							"value":    value,
						},
					})
					edges = append(edges, com.Edge{
						Start: com.EdgeQuery{Value: policyIdentifier + "-" + fmt.Sprint(index), Kind: cfg.BaseLabel},
						End:   com.EdgeQuery{Value: policyIdentifier + "-stmt-" + fmt.Sprint(index) + "-" + operator + "-" + key + "-" + value, Kind: cfg.BaseLabel},
						Kind:  "HAS_CONDITION",
					})
				}
			}
		}
	}
	return nodes, edges
}

func (c *IAMService) GetInlinePolicies(ctx context.Context, policyDocument *string, policyName string, arn string) ([]com.Node, []com.Edge) {
	allNodes := []com.Node{}
	allEdges := []com.Edge{}

	allNodes = append(allNodes, com.Node{
		Id:    arn + "-" + policyName,
		Kinds: []string{"InlinePolicy"},
	})
	allEdges = append(allEdges, com.Edge{
		Start: com.EdgeQuery{Value: arn, Kind: cfg.BaseLabel},
		End:   com.EdgeQuery{Value: arn + "-" + policyName, Kind: cfg.BaseLabel},
		Kind:  "HAS_INLINE_POLICY",
	})

	policyNodes, policyEdges := c.DecodePolicyDocument(ctx, policyDocument, arn+"-"+policyName)
	allNodes = append(allNodes, policyNodes...)
	allEdges = append(allEdges, policyEdges...)
	return allNodes, allEdges
}
