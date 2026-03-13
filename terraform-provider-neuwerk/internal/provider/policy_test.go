package provider

import "testing"

func TestNormalizeDocumentJSONCanonicalizes(t *testing.T) {
	t.Parallel()

	canonical, raw, err := normalizeDocumentJSON([]byte(`{"source_groups":[],"default_policy":"deny"}`))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	expected := "{\n  \"default_policy\": \"deny\",\n  \"source_groups\": []\n}"
	if canonical != expected {
		t.Fatalf("unexpected canonical json:\n%s", canonical)
	}
	if string(raw) != expected {
		t.Fatalf("unexpected raw json:\n%s", string(raw))
	}
}

func TestNormalizeDocumentJSONRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	if _, _, err := normalizeDocumentJSON([]byte(`{"default_policy":`)); err == nil {
		t.Fatalf("expected invalid json error")
	}
}

func TestCompileSugarPolicyBuildsDNSAndTLSVariants(t *testing.T) {
	t.Parallel()

	compiled, _, err := compileSugarPolicy(policyCompilerInput{
		DefaultAction: "deny",
		SourceGroups: []policySourceGroupInput{
			{
				ID: "corp-clients",
				Sources: policySourcesInput{
					CIDRs: []string{"10.20.0.0/16"},
				},
				Rules: []policyRuleInput{
					{
						ID:     "allow-dns",
						Action: "allow",
						DNS: &policyDNSInput{
							Exact:    []string{"GitHub.com", "api.github.com"},
							Suffixes: []string{"Example.com"},
						},
					},
					{
						ID:     "allow-external-secrets",
						Action: "allow",
						Destination: &policyDestinationInput{
							Protocol: "tcp",
							Ports:    []int64{443},
						},
						TLS: &policyTLSInput{
							Mode: "intercept",
							Request: &policyTLSRequestInput{
								Methods: []string{"get"},
								Targets: []policyTLSTargetInput{
									{
										Hosts:      []string{"vault-b.example.com", "Vault-A.example.com"},
										PathPrefix: []string{"/external-secrets/"},
									},
									{
										Hosts:      []string{"secrets.internal.example.com"},
										PathPrefix: []string{"/v1/"},
									},
								},
							},
							Response: &policyTLSResponseInput{
								DenyHeaders: []string{"X-Forbidden"},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile sugar policy: %v", err)
	}

	expected := "{\n  \"default_policy\": \"deny\",\n  \"source_groups\": [\n    {\n      \"id\": \"corp-clients\",\n      \"rules\": [\n        {\n          \"action\": \"allow\",\n          \"id\": \"allow-dns\",\n          \"match\": {\n            \"dns_hostname\": \"^(?:api\\\\.github\\\\.com|github\\\\.com|(?:.+\\\\.)?example\\\\.com)$\"\n          },\n          \"mode\": \"enforce\"\n        },\n        {\n          \"action\": \"allow\",\n          \"id\": \"allow-external-secrets-1\",\n          \"match\": {\n            \"dst_ports\": [\n              443\n            ],\n            \"proto\": \"tcp\",\n            \"tls\": {\n              \"http\": {\n                \"request\": {\n                  \"host\": {\n                    \"exact\": [\n                      \"vault-a.example.com\",\n                      \"vault-b.example.com\"\n                    ]\n                  },\n                  \"methods\": [\n                    \"GET\"\n                  ],\n                  \"path\": {\n                    \"prefix\": [\n                      \"/external-secrets/\"\n                    ]\n                  }\n                },\n                \"response\": {\n                  \"headers\": {\n                    \"deny_present\": [\n                      \"x-forbidden\"\n                    ]\n                  }\n                }\n              },\n              \"mode\": \"intercept\"\n            }\n          },\n          \"mode\": \"enforce\"\n        },\n        {\n          \"action\": \"allow\",\n          \"id\": \"allow-external-secrets-2\",\n          \"match\": {\n            \"dst_ports\": [\n              443\n            ],\n            \"proto\": \"tcp\",\n            \"tls\": {\n              \"http\": {\n                \"request\": {\n                  \"host\": {\n                    \"exact\": [\n                      \"secrets.internal.example.com\"\n                    ]\n                  },\n                  \"methods\": [\n                    \"GET\"\n                  ],\n                  \"path\": {\n                    \"prefix\": [\n                      \"/v1/\"\n                    ]\n                  }\n                },\n                \"response\": {\n                  \"headers\": {\n                    \"deny_present\": [\n                      \"x-forbidden\"\n                    ]\n                  }\n                }\n              },\n              \"mode\": \"intercept\"\n            }\n          },\n          \"mode\": \"enforce\"\n        }\n      ],\n      \"sources\": {\n        \"cidrs\": [\n          \"10.20.0.0/16\"\n        ]\n      }\n    }\n  ]\n}"
	if compiled != expected {
		t.Fatalf("unexpected compiled policy:\n%s", compiled)
	}
}

func TestCompileSugarPolicyRejectsEmptyDNSMatcher(t *testing.T) {
	t.Parallel()

	_, _, err := compileSugarPolicy(policyCompilerInput{
		SourceGroups: []policySourceGroupInput{
			{
				ID: "g1",
				Sources: policySourcesInput{
					IPs: []string{"10.0.0.5"},
				},
				Rules: []policyRuleInput{
					{
						ID:     "r1",
						Action: "allow",
						DNS:    &policyDNSInput{},
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatalf("expected dns compilation error")
	}
}

func TestCompileSugarPolicyBuildsKubernetesSelectorsAndGroupDefaultAction(t *testing.T) {
	t.Parallel()

	compiled, _, err := compileSugarPolicy(policyCompilerInput{
		DefaultAction: "deny",
		SourceGroups: []policySourceGroupInput{
			{
				ID:            "pods",
				Priority:      int64Ptr(10),
				DefaultAction: "deny",
				Sources: policySourcesInput{
					KubernetesSelectors: []policyKubernetesSelectorInput{
						{
							Integration: "prod-k8s",
							PodSelector: &policyPodSelectorInput{
								Namespace: "apps",
								MatchLabels: map[string]string{
									"tier": "backend",
									"app":  "api",
								},
							},
						},
						{
							Integration: "prod-k8s",
							NodeSelector: &policyNodeSelectorInput{
								MatchLabels: map[string]string{
									"nodepool": "blue",
								},
							},
						},
					},
				},
				Rules: []policyRuleInput{
					{
						ID:       "allow-https",
						Priority: int64Ptr(10),
						Action:   "allow",
						Mode:     "audit",
						Destination: &policyDestinationInput{
							Protocol: "tcp",
							Ports:    []int64{443},
							IPs:      []string{"203.0.113.10"},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile sugar policy: %v", err)
	}

	expected := "{\n  \"default_policy\": \"deny\",\n  \"source_groups\": [\n    {\n      \"default_action\": \"deny\",\n      \"id\": \"pods\",\n      \"priority\": 10,\n      \"rules\": [\n        {\n          \"action\": \"allow\",\n          \"id\": \"allow-https\",\n          \"match\": {\n            \"dst_ips\": [\n              \"203.0.113.10\"\n            ],\n            \"dst_ports\": [\n              443\n            ],\n            \"proto\": \"tcp\"\n          },\n          \"mode\": \"audit\",\n          \"priority\": 10\n        }\n      ],\n      \"sources\": {\n        \"kubernetes\": [\n          {\n            \"integration\": \"prod-k8s\",\n            \"pod_selector\": {\n              \"match_labels\": {\n                \"app\": \"api\",\n                \"tier\": \"backend\"\n              },\n              \"namespace\": \"apps\"\n            }\n          },\n          {\n            \"integration\": \"prod-k8s\",\n            \"node_selector\": {\n              \"match_labels\": {\n                \"nodepool\": \"blue\"\n              }\n            }\n          }\n        ]\n      }\n    }\n  ]\n}"
	if compiled != expected {
		t.Fatalf("unexpected compiled policy:\n%s", compiled)
	}
}

func int64Ptr(value int64) *int64 {
	return &value
}
