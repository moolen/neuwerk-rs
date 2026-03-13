package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

type policySourceGroupModel struct {
	ID            types.String `tfsdk:"id"`
	Priority      types.Int64  `tfsdk:"priority"`
	DefaultAction types.String `tfsdk:"default_action"`
	Sources       types.Object `tfsdk:"sources"`
	Rules         types.List   `tfsdk:"rule"`
}

type policySourcesModel struct {
	CIDRs               types.List `tfsdk:"cidrs"`
	IPs                 types.List `tfsdk:"ips"`
	KubernetesSelectors types.List `tfsdk:"kubernetes_selector"`
}

type policyKubernetesSelectorModel struct {
	Integration  types.String `tfsdk:"integration"`
	PodSelector  types.Object `tfsdk:"pod_selector"`
	NodeSelector types.Object `tfsdk:"node_selector"`
}

type policyPodSelectorModel struct {
	Namespace   types.String `tfsdk:"namespace"`
	MatchLabels types.Map    `tfsdk:"match_labels"`
}

type policyNodeSelectorModel struct {
	MatchLabels types.Map `tfsdk:"match_labels"`
}

type policyRuleModel struct {
	ID          types.String `tfsdk:"id"`
	Priority    types.Int64  `tfsdk:"priority"`
	Action      types.String `tfsdk:"action"`
	Mode        types.String `tfsdk:"mode"`
	DNS         types.Object `tfsdk:"dns"`
	Destination types.Object `tfsdk:"destination"`
	TLS         types.Object `tfsdk:"tls"`
}

type policyDNSModel struct {
	Exact    types.List `tfsdk:"exact"`
	Suffixes types.List `tfsdk:"suffixes"`
}

type policyDestinationModel struct {
	Protocol types.String `tfsdk:"protocol"`
	Ports    types.List   `tfsdk:"ports"`
	CIDRs    types.List   `tfsdk:"cidrs"`
	IPs      types.List   `tfsdk:"ips"`
}

type policyTLSModel struct {
	Mode     types.String `tfsdk:"mode"`
	Request  types.Object `tfsdk:"request"`
	Response types.Object `tfsdk:"response"`
}

type policyTLSRequestModel struct {
	Methods        types.List `tfsdk:"methods"`
	RequireHeaders types.List `tfsdk:"require_headers"`
	DenyHeaders    types.List `tfsdk:"deny_headers"`
	Targets        types.List `tfsdk:"target"`
}

type policyTLSTargetModel struct {
	Hosts      types.List   `tfsdk:"hosts"`
	PathExact  types.List   `tfsdk:"path_exact"`
	PathPrefix types.List   `tfsdk:"path_prefix"`
	PathRegex  types.String `tfsdk:"path_regex"`
}

type policyTLSResponseModel struct {
	DenyHeaders types.List `tfsdk:"deny_headers"`
}

type policyCompilerInput struct {
	DefaultAction string
	SourceGroups  []policySourceGroupInput
}

type policySourceGroupInput struct {
	ID            string
	Priority      *int64
	DefaultAction string
	Sources       policySourcesInput
	Rules         []policyRuleInput
}

type policySourcesInput struct {
	CIDRs               []string
	IPs                 []string
	KubernetesSelectors []policyKubernetesSelectorInput
}

type policyKubernetesSelectorInput struct {
	Integration  string
	PodSelector  *policyPodSelectorInput
	NodeSelector *policyNodeSelectorInput
}

type policyPodSelectorInput struct {
	Namespace   string
	MatchLabels map[string]string
}

type policyNodeSelectorInput struct {
	MatchLabels map[string]string
}

type policyRuleInput struct {
	ID          string
	Priority    *int64
	Action      string
	Mode        string
	DNS         *policyDNSInput
	Destination *policyDestinationInput
	TLS         *policyTLSInput
}

type policyDNSInput struct {
	Exact    []string
	Suffixes []string
}

type policyDestinationInput struct {
	Protocol string
	Ports    []int64
	CIDRs    []string
	IPs      []string
}

type policyTLSInput struct {
	Mode     string
	Request  *policyTLSRequestInput
	Response *policyTLSResponseInput
}

type policyTLSRequestInput struct {
	Methods        []string
	RequireHeaders []string
	DenyHeaders    []string
	Targets        []policyTLSTargetInput
}

type policyTLSTargetInput struct {
	Hosts      []string
	PathExact  []string
	PathPrefix []string
	PathRegex  string
}

type policyTLSResponseInput struct {
	DenyHeaders []string
}

func policyInputFromModel(ctx context.Context, plan policyResourceModel) (policyCompilerInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	input := policyCompilerInput{
		DefaultAction: strings.TrimSpace(plan.DefaultAction.ValueString()),
	}

	if !plan.SourceGroups.IsNull() && !plan.SourceGroups.IsUnknown() {
		var groups []policySourceGroupModel
		diags.Append(plan.SourceGroups.ElementsAs(ctx, &groups, false)...)
		if diags.HasError() {
			return input, diags
		}

		input.SourceGroups = make([]policySourceGroupInput, 0, len(groups))
		for idx, group := range groups {
			decoded, groupDiags := decodePolicySourceGroup(ctx, group, path.Root("source_group").AtListIndex(idx))
			diags.Append(groupDiags...)
			if diags.HasError() {
				return input, diags
			}
			input.SourceGroups = append(input.SourceGroups, decoded)
		}
	}

	return input, diags
}

func decodePolicySourceGroup(ctx context.Context, group policySourceGroupModel, p path.Path) (policySourceGroupInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	input := policySourceGroupInput{
		ID:            strings.TrimSpace(group.ID.ValueString()),
		DefaultAction: strings.TrimSpace(group.DefaultAction.ValueString()),
	}
	if input.ID == "" {
		diags.AddAttributeError(p.AtName("id"), "Missing Source Group ID", "source_group.id must not be empty.")
		return input, diags
	}
	if !group.Priority.IsNull() && !group.Priority.IsUnknown() {
		value := group.Priority.ValueInt64()
		input.Priority = &value
	}

	var sources policySourcesModel
	diags.Append(group.Sources.As(ctx, &sources, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return input, diags
	}
	input.Sources, diags = decodePolicySources(ctx, sources, p.AtName("sources"))
	if diags.HasError() {
		return input, diags
	}

	if !group.Rules.IsNull() && !group.Rules.IsUnknown() {
		var rules []policyRuleModel
		diags.Append(group.Rules.ElementsAs(ctx, &rules, false)...)
		if diags.HasError() {
			return input, diags
		}
		input.Rules = make([]policyRuleInput, 0, len(rules))
		for idx, rule := range rules {
			decoded, ruleDiags := decodePolicyRule(ctx, rule, p.AtName("rule").AtListIndex(idx))
			diags.Append(ruleDiags...)
			if diags.HasError() {
				return input, diags
			}
			input.Rules = append(input.Rules, decoded)
		}
	}

	return input, diags
}

func decodePolicySources(ctx context.Context, sources policySourcesModel, p path.Path) (policySourcesInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	cidrs, cidrDiags := listStrings(ctx, sources.CIDRs)
	ips, ipDiags := listStrings(ctx, sources.IPs)
	diags.Append(cidrDiags...)
	diags.Append(ipDiags...)

	input := policySourcesInput{
		CIDRs: cidrs,
		IPs:   ips,
	}

	if !sources.KubernetesSelectors.IsNull() && !sources.KubernetesSelectors.IsUnknown() {
		var selectors []policyKubernetesSelectorModel
		diags.Append(sources.KubernetesSelectors.ElementsAs(ctx, &selectors, false)...)
		if diags.HasError() {
			return input, diags
		}
		input.KubernetesSelectors = make([]policyKubernetesSelectorInput, 0, len(selectors))
		for idx, selector := range selectors {
			decoded, selectorDiags := decodePolicyKubernetesSelector(ctx, selector, p.AtName("kubernetes_selector").AtListIndex(idx))
			diags.Append(selectorDiags...)
			if diags.HasError() {
				return input, diags
			}
			input.KubernetesSelectors = append(input.KubernetesSelectors, decoded)
		}
	}

	return input, diags
}

func decodePolicyKubernetesSelector(ctx context.Context, selector policyKubernetesSelectorModel, p path.Path) (policyKubernetesSelectorInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	input := policyKubernetesSelectorInput{
		Integration: strings.TrimSpace(selector.Integration.ValueString()),
	}
	if input.Integration == "" {
		diags.AddAttributeError(p.AtName("integration"), "Missing Integration", "kubernetes_selector.integration must not be empty.")
		return input, diags
	}

	if !selector.PodSelector.IsNull() && !selector.PodSelector.IsUnknown() {
		var pod policyPodSelectorModel
		diags.Append(selector.PodSelector.As(ctx, &pod, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return input, diags
		}
		labels, labelDiags := mapStrings(ctx, pod.MatchLabels)
		diags.Append(labelDiags...)
		input.PodSelector = &policyPodSelectorInput{
			Namespace:   strings.TrimSpace(pod.Namespace.ValueString()),
			MatchLabels: labels,
		}
	}

	if !selector.NodeSelector.IsNull() && !selector.NodeSelector.IsUnknown() {
		var node policyNodeSelectorModel
		diags.Append(selector.NodeSelector.As(ctx, &node, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return input, diags
		}
		labels, labelDiags := mapStrings(ctx, node.MatchLabels)
		diags.Append(labelDiags...)
		input.NodeSelector = &policyNodeSelectorInput{
			MatchLabels: labels,
		}
	}

	return input, diags
}

func decodePolicyRule(ctx context.Context, rule policyRuleModel, p path.Path) (policyRuleInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	input := policyRuleInput{
		ID:     strings.TrimSpace(rule.ID.ValueString()),
		Action: strings.TrimSpace(rule.Action.ValueString()),
		Mode:   strings.TrimSpace(rule.Mode.ValueString()),
	}
	if input.ID == "" {
		diags.AddAttributeError(p.AtName("id"), "Missing Rule ID", "rule.id must not be empty.")
	}
	if input.Action == "" {
		diags.AddAttributeError(p.AtName("action"), "Missing Rule Action", "rule.action must not be empty.")
	}
	if diags.HasError() {
		return input, diags
	}
	if !rule.Priority.IsNull() && !rule.Priority.IsUnknown() {
		value := rule.Priority.ValueInt64()
		input.Priority = &value
	}

	if !rule.DNS.IsNull() && !rule.DNS.IsUnknown() {
		var dns policyDNSModel
		diags.Append(rule.DNS.As(ctx, &dns, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return input, diags
		}
		exact, exactDiags := listStrings(ctx, dns.Exact)
		suffixes, suffixDiags := listStrings(ctx, dns.Suffixes)
		diags.Append(exactDiags...)
		diags.Append(suffixDiags...)
		input.DNS = &policyDNSInput{Exact: exact, Suffixes: suffixes}
	}

	if !rule.Destination.IsNull() && !rule.Destination.IsUnknown() {
		var destination policyDestinationModel
		diags.Append(rule.Destination.As(ctx, &destination, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return input, diags
		}
		ports, portDiags := listInt64s(ctx, destination.Ports)
		cidrs, cidrDiags := listStrings(ctx, destination.CIDRs)
		ips, ipDiags := listStrings(ctx, destination.IPs)
		diags.Append(portDiags...)
		diags.Append(cidrDiags...)
		diags.Append(ipDiags...)
		input.Destination = &policyDestinationInput{
			Protocol: strings.TrimSpace(destination.Protocol.ValueString()),
			Ports:    ports,
			CIDRs:    cidrs,
			IPs:      ips,
		}
	}

	if !rule.TLS.IsNull() && !rule.TLS.IsUnknown() {
		var tlsModel policyTLSModel
		diags.Append(rule.TLS.As(ctx, &tlsModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return input, diags
		}
		tlsInput := &policyTLSInput{
			Mode: strings.TrimSpace(tlsModel.Mode.ValueString()),
		}
		if !tlsModel.Request.IsNull() && !tlsModel.Request.IsUnknown() {
			var request policyTLSRequestModel
			diags.Append(tlsModel.Request.As(ctx, &request, basetypes.ObjectAsOptions{})...)
			if diags.HasError() {
				return input, diags
			}
			methods, methodDiags := listStrings(ctx, request.Methods)
			requireHeaders, requireDiags := listStrings(ctx, request.RequireHeaders)
			denyHeaders, denyDiags := listStrings(ctx, request.DenyHeaders)
			diags.Append(methodDiags...)
			diags.Append(requireDiags...)
			diags.Append(denyDiags...)
			requestInput := &policyTLSRequestInput{
				Methods:        methods,
				RequireHeaders: requireHeaders,
				DenyHeaders:    denyHeaders,
			}
			if !request.Targets.IsNull() && !request.Targets.IsUnknown() {
				var targets []policyTLSTargetModel
				diags.Append(request.Targets.ElementsAs(ctx, &targets, false)...)
				if diags.HasError() {
					return input, diags
				}
				requestInput.Targets = make([]policyTLSTargetInput, 0, len(targets))
				for idx, target := range targets {
					hosts, hostDiags := listStrings(ctx, target.Hosts)
					pathExact, exactDiags := listStrings(ctx, target.PathExact)
					pathPrefix, prefixDiags := listStrings(ctx, target.PathPrefix)
					diags.Append(hostDiags...)
					diags.Append(exactDiags...)
					diags.Append(prefixDiags...)
					if diags.HasError() {
						return input, diags
					}
					requestInput.Targets = append(requestInput.Targets, policyTLSTargetInput{
						Hosts:      hosts,
						PathExact:  pathExact,
						PathPrefix: pathPrefix,
						PathRegex:  strings.TrimSpace(target.PathRegex.ValueString()),
					})
					if len(hosts) == 0 {
						diags.AddAttributeError(
							p.AtName("tls").AtName("request").AtName("target").AtListIndex(idx).AtName("hosts"),
							"Missing Target Hosts",
							"tls.request.target.hosts must contain at least one hostname.",
						)
						return input, diags
					}
				}
			}
			tlsInput.Request = requestInput
		}

		if !tlsModel.Response.IsNull() && !tlsModel.Response.IsUnknown() {
			var response policyTLSResponseModel
			diags.Append(tlsModel.Response.As(ctx, &response, basetypes.ObjectAsOptions{})...)
			if diags.HasError() {
				return input, diags
			}
			denyHeaders, denyDiags := listStrings(ctx, response.DenyHeaders)
			diags.Append(denyDiags...)
			tlsInput.Response = &policyTLSResponseInput{
				DenyHeaders: denyHeaders,
			}
		}

		input.TLS = tlsInput
	}

	return input, diags
}

func compileSugarPolicy(input policyCompilerInput) (string, json.RawMessage, error) {
	document := map[string]any{
		"source_groups": make([]any, 0, len(input.SourceGroups)),
	}
	if strings.TrimSpace(input.DefaultAction) != "" {
		action, err := normalizePolicyAction(input.DefaultAction)
		if err != nil {
			return "", nil, err
		}
		document["default_policy"] = action
	}

	sourceGroups := make([]any, 0, len(input.SourceGroups))
	for groupIndex, group := range input.SourceGroups {
		groupMap, err := compileSourceGroup(group, groupIndex)
		if err != nil {
			return "", nil, err
		}
		sourceGroups = append(sourceGroups, groupMap)
	}
	document["source_groups"] = sourceGroups

	payload, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", nil, err
	}
	return string(payload), json.RawMessage(payload), nil
}

func compileSourceGroup(group policySourceGroupInput, groupIndex int) (map[string]any, error) {
	sources, err := compileSources(group.ID, group.Sources)
	if err != nil {
		return nil, err
	}
	groupMap := map[string]any{
		"id":      group.ID,
		"sources": sources,
	}
	if group.Priority != nil {
		groupMap["priority"] = *group.Priority
	}
	if strings.TrimSpace(group.DefaultAction) != "" {
		action, err := normalizePolicyAction(group.DefaultAction)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", group.ID, err)
		}
		groupMap["default_action"] = action
	}

	rules := make([]any, 0, len(group.Rules))
	for ruleIndex, rule := range group.Rules {
		compiledRules, err := compileRule(rule, ruleIndex)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", group.ID, err)
		}
		for _, compiledRule := range compiledRules {
			rules = append(rules, compiledRule)
		}
	}
	groupMap["rules"] = rules

	if group.Priority == nil && groupIndex >= 0 {
		// Preserve author order in the generated JSON while letting the server
		// continue to apply its fallback priority semantics.
	}

	return groupMap, nil
}

func compileSources(groupID string, sources policySourcesInput) (map[string]any, error) {
	cidrs := uniqueSortedStrings(sources.CIDRs, false)
	ips := uniqueSortedStrings(sources.IPs, false)
	kubernetes := make([]any, 0, len(sources.KubernetesSelectors))
	for _, selector := range sources.KubernetesSelectors {
		item := map[string]any{
			"integration": strings.TrimSpace(selector.Integration),
		}
		switch {
		case selector.PodSelector != nil && selector.NodeSelector != nil:
			return nil, fmt.Errorf("group %s: kubernetes selector must set exactly one of pod_selector or node_selector", groupID)
		case selector.PodSelector != nil:
			item["pod_selector"] = map[string]any{
				"namespace":    strings.TrimSpace(selector.PodSelector.Namespace),
				"match_labels": normalizeLabelMap(selector.PodSelector.MatchLabels),
			}
		case selector.NodeSelector != nil:
			item["node_selector"] = map[string]any{
				"match_labels": normalizeLabelMap(selector.NodeSelector.MatchLabels),
			}
		default:
			return nil, fmt.Errorf("group %s: kubernetes selector must set pod_selector or node_selector", groupID)
		}
		kubernetes = append(kubernetes, item)
	}

	if len(cidrs) == 0 && len(ips) == 0 && len(kubernetes) == 0 {
		return nil, fmt.Errorf("group %s: sources cannot be empty", groupID)
	}

	result := map[string]any{}
	if len(cidrs) > 0 {
		result["cidrs"] = cidrs
	}
	if len(ips) > 0 {
		result["ips"] = ips
	}
	if len(kubernetes) > 0 {
		result["kubernetes"] = kubernetes
	}
	return result, nil
}

func compileRule(rule policyRuleInput, ruleIndex int) ([]map[string]any, error) {
	action, err := normalizePolicyAction(rule.Action)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	mode, err := normalizeRuleMode(rule.Mode)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
	}

	baseMatch := map[string]any{}
	if rule.DNS != nil {
		dnsRegex, err := compileDNSSugar(*rule.DNS)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		baseMatch["dns_hostname"] = dnsRegex
	}
	if rule.Destination != nil {
		if err := applyDestination(baseMatch, *rule.Destination); err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
	}

	tlsVariants := []map[string]any{nil}
	if rule.TLS != nil {
		tlsVariants, err = compileTLSVariants(rule.ID, *rule.TLS)
		if err != nil {
			return nil, err
		}
	}

	rules := make([]map[string]any, 0, len(tlsVariants))
	for idx, tlsVariant := range tlsVariants {
		match := cloneMap(baseMatch)
		if tlsVariant != nil {
			match["tls"] = tlsVariant
		}

		entry := map[string]any{
			"id":     generatedRuleID(rule.ID, len(tlsVariants), idx),
			"action": action,
			"mode":   mode,
			"match":  match,
		}
		if rule.Priority != nil {
			priority := *rule.Priority
			if len(tlsVariants) > 1 {
				priority += int64(idx)
			}
			entry["priority"] = priority
		}
		if rule.Priority == nil && len(tlsVariants) > 1 {
			_ = ruleIndex
		}
		rules = append(rules, entry)
	}

	return rules, nil
}

func compileDNSSugar(input policyDNSInput) (string, error) {
	exacts := uniqueSortedStrings(input.Exact, true)
	suffixes := uniqueSortedStrings(input.Suffixes, true)
	parts := make([]string, 0, len(exacts)+len(suffixes))
	for _, host := range exacts {
		parts = append(parts, regexp.QuoteMeta(host))
	}
	for _, suffix := range suffixes {
		parts = append(parts, fmt.Sprintf("(?:.+\\.)?%s", regexp.QuoteMeta(suffix)))
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("dns matcher requires exact and/or suffixes")
	}
	return "^(?:" + strings.Join(parts, "|") + ")$", nil
}

func applyDestination(match map[string]any, input policyDestinationInput) error {
	protocol := strings.TrimSpace(strings.ToLower(input.Protocol))
	if protocol != "" {
		switch protocol {
		case "any", "tcp", "udp", "icmp":
			match["proto"] = protocol
		default:
			return fmt.Errorf("destination.protocol must be one of any, tcp, udp, or icmp")
		}
	}

	ports := uniqueSortedInt64s(input.Ports)
	if len(ports) > 0 {
		match["dst_ports"] = ports
	}
	cidrs := uniqueSortedStrings(input.CIDRs, false)
	if len(cidrs) > 0 {
		match["dst_cidrs"] = cidrs
	}
	ips := uniqueSortedStrings(input.IPs, false)
	if len(ips) > 0 {
		match["dst_ips"] = ips
	}
	return nil
}

func compileTLSVariants(ruleID string, input policyTLSInput) ([]map[string]any, error) {
	mode := strings.TrimSpace(strings.ToLower(input.Mode))
	switch mode {
	case "metadata":
		if input.Request != nil || input.Response != nil {
			return nil, fmt.Errorf("rule %s: tls.mode metadata cannot be combined with intercept http sugar", ruleID)
		}
		return []map[string]any{{"mode": "metadata"}}, nil
	case "intercept":
	default:
		return nil, fmt.Errorf("rule %s: tls.mode must be metadata or intercept", ruleID)
	}

	responseMap, hasResponse, err := compileTLSResponse(ruleID, input.Response)
	if err != nil {
		return nil, err
	}
	requestCommon, targets, hasRequest, err := compileTLSRequest(ruleID, input.Request)
	if err != nil {
		return nil, err
	}
	if !hasRequest && !hasResponse {
		return nil, fmt.Errorf("rule %s: tls.mode intercept requires request and/or response constraints", ruleID)
	}

	if len(targets) == 0 {
		httpPolicy := map[string]any{}
		if hasRequest {
			httpPolicy["request"] = requestCommon
		}
		if hasResponse {
			httpPolicy["response"] = responseMap
		}
		return []map[string]any{{
			"mode": "intercept",
			"http": httpPolicy,
		}}, nil
	}

	variants := make([]map[string]any, 0, len(targets))
	for _, target := range targets {
		requestMap := mergeRequestTarget(requestCommon, target)
		httpPolicy := map[string]any{
			"request": requestMap,
		}
		if hasResponse {
			httpPolicy["response"] = responseMap
		}
		variants = append(variants, map[string]any{
			"mode": "intercept",
			"http": httpPolicy,
		})
	}
	return variants, nil
}

func compileTLSRequest(ruleID string, input *policyTLSRequestInput) (map[string]any, []map[string]any, bool, error) {
	if input == nil {
		return nil, nil, false, nil
	}

	request := map[string]any{}
	methods := uniqueSortedUpperStrings(input.Methods)
	if len(methods) > 0 {
		request["methods"] = methods
	}

	headers := map[string]any{}
	requireHeaders := uniqueSortedHeaderNames(input.RequireHeaders)
	denyHeaders := uniqueSortedHeaderNames(input.DenyHeaders)
	if len(requireHeaders) > 0 {
		headers["require_present"] = requireHeaders
	}
	if len(denyHeaders) > 0 {
		headers["deny_present"] = denyHeaders
	}
	if len(headers) > 0 {
		request["headers"] = headers
	}

	targets := make([]map[string]any, 0, len(input.Targets))
	for _, target := range input.Targets {
		hosts := uniqueSortedStrings(target.Hosts, true)
		if len(hosts) == 0 {
			return nil, nil, false, fmt.Errorf("rule %s: tls.request.target.hosts cannot be empty", ruleID)
		}
		targetMap := map[string]any{
			"host": map[string]any{
				"exact": hosts,
			},
		}
		path := map[string]any{}
		exact := uniqueSortedStrings(target.PathExact, false)
		prefix := uniqueSortedStrings(target.PathPrefix, false)
		if len(exact) > 0 {
			path["exact"] = exact
		}
		if len(prefix) > 0 {
			path["prefix"] = prefix
		}
		if regex := strings.TrimSpace(target.PathRegex); regex != "" {
			path["regex"] = regex
		}
		if len(path) > 0 {
			targetMap["path"] = path
		}
		targets = append(targets, targetMap)
	}

	hasRequest := len(request) > 0 || len(targets) > 0
	return request, targets, hasRequest, nil
}

func compileTLSResponse(ruleID string, input *policyTLSResponseInput) (map[string]any, bool, error) {
	if input == nil {
		return nil, false, nil
	}
	denyHeaders := uniqueSortedHeaderNames(input.DenyHeaders)
	if len(denyHeaders) == 0 {
		return nil, false, fmt.Errorf("rule %s: tls.response requires deny_headers", ruleID)
	}
	return map[string]any{
		"headers": map[string]any{
			"deny_present": denyHeaders,
		},
	}, true, nil
}

func mergeRequestTarget(common map[string]any, target map[string]any) map[string]any {
	merged := cloneMap(common)
	for key, value := range target {
		merged[key] = value
	}
	return merged
}

func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func generatedRuleID(base string, total int, idx int) string {
	if total <= 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, idx+1)
}

func normalizePolicyAction(value string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(value))
	switch normalized {
	case "allow", "deny":
		return normalized, nil
	default:
		return "", fmt.Errorf("action must be allow or deny")
	}
}

func normalizeRuleMode(value string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(value))
	if normalized == "" {
		return "enforce", nil
	}
	switch normalized {
	case "audit", "enforce":
		return normalized, nil
	default:
		return "", fmt.Errorf("rule mode must be audit or enforce")
	}
}

func uniqueSortedStrings(values []string, lowercase bool) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lowercase {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedUpperStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedHeaderNames(values []string) []string {
	return uniqueSortedStrings(values, true)
}

func uniqueSortedInt64s(values []int64) []int64 {
	seen := map[int64]struct{}{}
	out := make([]int64, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func normalizeLabelMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		keys = append(keys, trimmed)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(keys))
	for _, key := range keys {
		value := strings.TrimSpace(input[key])
		if value == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func listStrings(ctx context.Context, value types.List) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if value.IsNull() || value.IsUnknown() {
		return nil, diags
	}
	var out []string
	diags.Append(value.ElementsAs(ctx, &out, false)...)
	return out, diags
}

func listInt64s(ctx context.Context, value types.List) ([]int64, diag.Diagnostics) {
	var diags diag.Diagnostics
	if value.IsNull() || value.IsUnknown() {
		return nil, diags
	}
	var out []int64
	diags.Append(value.ElementsAs(ctx, &out, false)...)
	return out, diags
}

func mapStrings(ctx context.Context, value types.Map) (map[string]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if value.IsNull() || value.IsUnknown() {
		return map[string]string{}, diags
	}
	out := map[string]string{}
	diags.Append(value.ElementsAs(ctx, &out, false)...)
	return out, diags
}
