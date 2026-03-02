import type { PolicyCreateRequest, PolicyTlsNameMatch } from '../types';

export interface PolicyValidationIssue {
  path: string;
  message: string;
}

function isValidRegex(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

function isValidPortSpec(value: string): boolean {
  const trimmed = value.trim();
  const match = /^(\d{1,5})(\s*-\s*(\d{1,5}))?$/.exec(trimmed);
  if (!match) return false;
  const start = Number(match[1]);
  const end = match[3] ? Number(match[3]) : start;
  if (!Number.isInteger(start) || !Number.isInteger(end)) return false;
  if (start < 1 || start > 65535 || end < 1 || end > 65535) return false;
  return start <= end;
}

function isValidProto(value?: string): boolean {
  if (!value) return true;
  const proto = value.trim().toLowerCase();
  if (!proto) return true;
  if (proto === 'any' || proto === 'tcp' || proto === 'udp' || proto === 'icmp') return true;
  if (!/^\d+$/.test(proto)) return false;
  const n = Number(proto);
  return Number.isInteger(n) && n >= 0 && n <= 255;
}

function protoValue(value?: string): string {
  return (value ?? 'any').trim().toLowerCase() || 'any';
}

function validateTlsNameMatch(
  value: PolicyTlsNameMatch | undefined,
  basePath: string,
  issues: PolicyValidationIssue[]
) {
  if (!value) return;
  const exact = (value.exact ?? []).map((entry) => entry.trim()).filter(Boolean);
  const regex = value.regex?.trim() ?? '';
  if (!exact.length && !regex) {
    issues.push({
      path: basePath,
      message: 'Matcher cannot be empty; set exact and/or regex',
    });
    return;
  }
  if (regex && !isValidRegex(regex)) {
    issues.push({
      path: `${basePath}.regex`,
      message: 'Invalid regex',
    });
  }
}

export function validatePolicyRequest(
  request: PolicyCreateRequest,
  options?: { integrationNames?: Set<string> }
): PolicyValidationIssue[] {
  const issues: PolicyValidationIssue[] = [];
  const integrationNames = options?.integrationNames ?? new Set<string>();

  if (!request.mode || !['disabled', 'audit', 'enforce'].includes(request.mode)) {
    issues.push({ path: 'mode', message: 'Mode must be disabled, audit, or enforce' });
  }

  const groups = request.policy.source_groups ?? [];
  for (let gi = 0; gi < groups.length; gi += 1) {
    const group = groups[gi];
    const groupPath = `policy.source_groups[${gi}]`;

    if (!group.id.trim()) {
      issues.push({ path: `${groupPath}.id`, message: 'Source group id is required' });
    }
    if (typeof group.priority === 'number' && group.priority < 0) {
      issues.push({ path: `${groupPath}.priority`, message: 'Priority must be >= 0' });
    }
    if (group.default_action && !['allow', 'deny'].includes(group.default_action)) {
      issues.push({ path: `${groupPath}.default_action`, message: 'Default action must be allow or deny' });
    }

    const cidrs = (group.sources?.cidrs ?? []).map((entry) => entry.trim()).filter(Boolean);
    const ips = (group.sources?.ips ?? []).map((entry) => entry.trim()).filter(Boolean);
    const k8s = group.sources?.kubernetes ?? [];
    if (!cidrs.length && !ips.length && !k8s.length) {
      issues.push({
        path: `${groupPath}.sources`,
        message: 'At least one source is required (cidr, ip, or kubernetes selector)',
      });
    }

    for (let si = 0; si < k8s.length; si += 1) {
      const source = k8s[si];
      const sourcePath = `${groupPath}.sources.kubernetes[${si}]`;
      const integration = source.integration.trim();
      if (!integration) {
        issues.push({
          path: `${sourcePath}.integration`,
          message: 'Kubernetes integration is required',
        });
      } else if (integrationNames.size > 0 && !integrationNames.has(integration)) {
        issues.push({
          path: `${sourcePath}.integration`,
          message: `Unknown kubernetes integration: ${integration}`,
        });
      }

      const hasPod = !!source.pod_selector;
      const hasNode = !!source.node_selector;
      if (hasPod === hasNode) {
        issues.push({
          path: sourcePath,
          message: 'Set exactly one of pod selector or node selector',
        });
      }
      if (source.pod_selector) {
        if (!source.pod_selector.namespace.trim()) {
          issues.push({
            path: `${sourcePath}.pod_selector.namespace`,
            message: 'Namespace is required for pod selector',
          });
        }
        for (const [k, v] of Object.entries(source.pod_selector.match_labels ?? {})) {
          if (!k.trim() || !v.trim()) {
            issues.push({
              path: `${sourcePath}.pod_selector.match_labels`,
              message: 'Label keys and values must be non-empty',
            });
            break;
          }
        }
      }
      if (source.node_selector) {
        for (const [k, v] of Object.entries(source.node_selector.match_labels ?? {})) {
          if (!k.trim() || !v.trim()) {
            issues.push({
              path: `${sourcePath}.node_selector.match_labels`,
              message: 'Label keys and values must be non-empty',
            });
            break;
          }
        }
      }
    }

    const rules = group.rules ?? [];
    for (let ri = 0; ri < rules.length; ri += 1) {
      const rule = rules[ri];
      const rulePath = `${groupPath}.rules[${ri}]`;
      if (!rule.id.trim()) {
        issues.push({ path: `${rulePath}.id`, message: 'Rule id is required' });
      }
      if (typeof rule.priority === 'number' && rule.priority < 0) {
        issues.push({ path: `${rulePath}.priority`, message: 'Priority must be >= 0' });
      }
      if (!['allow', 'deny'].includes(rule.action)) {
        issues.push({ path: `${rulePath}.action`, message: 'Rule action must be allow or deny' });
      }
      if (rule.mode && !['audit', 'enforce'].includes(rule.mode)) {
        issues.push({ path: `${rulePath}.mode`, message: 'Rule mode must be audit or enforce' });
      }

      const match = rule.match;
      const proto = protoValue(match.proto);
      if (!isValidProto(match.proto)) {
        issues.push({ path: `${rulePath}.match.proto`, message: 'Protocol must be any/tcp/udp/icmp or 0-255' });
      }

      if (match.dns_hostname !== undefined) {
        const dns = match.dns_hostname.trim();
        if (!dns) {
          issues.push({ path: `${rulePath}.match.dns_hostname`, message: 'dns_hostname cannot be empty' });
        } else if (!isValidRegex(dns)) {
          issues.push({ path: `${rulePath}.match.dns_hostname`, message: 'dns_hostname must be a valid regex' });
        }
      }

      for (let pi = 0; pi < (match.src_ports ?? []).length; pi += 1) {
        if (!isValidPortSpec(match.src_ports[pi])) {
          issues.push({
            path: `${rulePath}.match.src_ports[${pi}]`,
            message: 'Invalid port spec (use 1-65535 or start-end)',
          });
        }
      }

      for (let pi = 0; pi < (match.dst_ports ?? []).length; pi += 1) {
        if (!isValidPortSpec(match.dst_ports[pi])) {
          issues.push({
            path: `${rulePath}.match.dst_ports[${pi}]`,
            message: 'Invalid port spec (use 1-65535 or start-end)',
          });
        }
      }

      if (proto === 'icmp' && ((match.src_ports ?? []).length || (match.dst_ports ?? []).length)) {
        issues.push({
          path: `${rulePath}.match`,
          message: 'ICMP rules cannot include src/dst port constraints',
        });
      }

      if (((match.icmp_types ?? []).length || (match.icmp_codes ?? []).length) && proto !== 'icmp' && proto !== 'any') {
        issues.push({
          path: `${rulePath}.match`,
          message: 'ICMP type/code requires proto icmp or any',
        });
      }

      for (let ii = 0; ii < (match.icmp_types ?? []).length; ii += 1) {
        const value = match.icmp_types[ii];
        if (!Number.isInteger(value) || value < 0 || value > 255) {
          issues.push({
            path: `${rulePath}.match.icmp_types[${ii}]`,
            message: 'ICMP types must be integers between 0 and 255',
          });
        }
      }
      for (let ii = 0; ii < (match.icmp_codes ?? []).length; ii += 1) {
        const value = match.icmp_codes[ii];
        if (!Number.isInteger(value) || value < 0 || value > 255) {
          issues.push({
            path: `${rulePath}.match.icmp_codes[${ii}]`,
            message: 'ICMP codes must be integers between 0 and 255',
          });
        }
      }

      if (!match.tls) continue;
      const tlsPath = `${rulePath}.match.tls`;
      if (proto !== 'tcp' && proto !== 'any') {
        issues.push({
          path: tlsPath,
          message: 'TLS match requires proto tcp or any',
        });
      }

      const tls = match.tls;
      const tlsMode = tls.mode ?? 'metadata';
      const hasMetadataMatchers =
        !!tls.sni ||
        !!tls.server_cn ||
        !!tls.server_san ||
        !!tls.server_dn?.trim() ||
        (tls.fingerprint_sha256 ?? []).length > 0 ||
        (tls.trust_anchors_pem ?? []).length > 0;
      const hasHttp = !!tls.http;

      validateTlsNameMatch(tls.sni, `${tlsPath}.sni`, issues);
      validateTlsNameMatch(tls.server_cn, `${tlsPath}.server_cn`, issues);
      validateTlsNameMatch(tls.server_san, `${tlsPath}.server_san`, issues);

      if (tls.server_dn !== undefined) {
        const serverDn = tls.server_dn.trim();
        if (!serverDn) {
          issues.push({
            path: `${tlsPath}.server_dn`,
            message: 'server_dn cannot be empty',
          });
        } else if (!isValidRegex(serverDn)) {
          issues.push({
            path: `${tlsPath}.server_dn`,
            message: 'server_dn must be a valid regex',
          });
        }
      }

      for (let fi = 0; fi < (tls.fingerprint_sha256 ?? []).length; fi += 1) {
        const fp = tls.fingerprint_sha256[fi].replace(/[\s:]/g, '');
        if (!/^[0-9a-fA-F]{64}$/.test(fp)) {
          issues.push({
            path: `${tlsPath}.fingerprint_sha256[${fi}]`,
            message: 'Fingerprint must be 64 hex chars (colons allowed)',
          });
        }
      }
      for (let ai = 0; ai < (tls.trust_anchors_pem ?? []).length; ai += 1) {
        const pem = tls.trust_anchors_pem[ai].trim();
        if (!pem) {
          issues.push({
            path: `${tlsPath}.trust_anchors_pem[${ai}]`,
            message: 'Trust anchor entry cannot be empty',
          });
        } else if (!pem.includes('-----BEGIN CERTIFICATE-----')) {
          issues.push({
            path: `${tlsPath}.trust_anchors_pem[${ai}]`,
            message: 'Trust anchor must contain a PEM certificate',
          });
        }
      }

      if (tls.http) {
        const hasRequest = !!tls.http.request;
        const hasResponse = !!tls.http.response;
        if (!hasRequest && !hasResponse) {
          issues.push({
            path: `${tlsPath}.http`,
            message: 'tls.http requires request and/or response constraints',
          });
        }
      }

      if (tlsMode === 'intercept') {
        if (hasMetadataMatchers) {
          issues.push({
            path: tlsPath,
            message: 'tls.mode intercept cannot be combined with metadata matchers',
          });
        }
        if (!hasHttp) {
          issues.push({
            path: tlsPath,
            message: 'tls.mode intercept requires tls.http constraints',
          });
        }
      } else if (tlsMode === 'metadata') {
        if (hasHttp) {
          issues.push({
            path: tlsPath,
            message: 'tls.http is only valid when tls.mode is intercept',
          });
        }
      } else {
        issues.push({
          path: `${tlsPath}.mode`,
          message: 'tls.mode must be metadata or intercept',
        });
      }

      if (!tls.http) continue;

      if (tls.http.request) {
        const req = tls.http.request;
        const reqPath = `${tlsPath}.http.request`;
        validateTlsNameMatch(req.host, `${reqPath}.host`, issues);

        for (let mi = 0; mi < (req.methods ?? []).length; mi += 1) {
          const method = req.methods[mi].trim();
          if (!method) {
            issues.push({
              path: `${reqPath}.methods[${mi}]`,
              message: 'HTTP method cannot be empty',
            });
          }
        }

        if (req.path) {
          const hasPath =
            (req.path.exact ?? []).some((v) => !!v.trim()) ||
            (req.path.prefix ?? []).some((v) => !!v.trim()) ||
            !!req.path.regex?.trim();
          if (!hasPath) {
            issues.push({
              path: `${reqPath}.path`,
              message: 'Path matcher cannot be empty',
            });
          }
          if (req.path.regex?.trim() && !isValidRegex(req.path.regex.trim())) {
            issues.push({
              path: `${reqPath}.path.regex`,
              message: 'Invalid regex',
            });
          }
        }

        if (req.query) {
          const hasQuery =
            (req.query.keys_present ?? []).some((v) => !!v.trim()) ||
            Object.keys(req.query.key_values_exact ?? {}).length > 0 ||
            Object.keys(req.query.key_values_regex ?? {}).length > 0;
          if (!hasQuery) {
            issues.push({
              path: `${reqPath}.query`,
              message: 'Query matcher cannot be empty',
            });
          }
          for (const [k, vals] of Object.entries(req.query.key_values_exact ?? {})) {
            if (!k.trim()) {
              issues.push({
                path: `${reqPath}.query.key_values_exact`,
                message: 'Exact query matcher key cannot be empty',
              });
            }
            if (!vals.length || !vals.some((v) => !!v.trim())) {
              issues.push({
                path: `${reqPath}.query.key_values_exact.${k}`,
                message: 'Exact query matcher values cannot be empty',
              });
            }
          }
          for (const [k, pattern] of Object.entries(req.query.key_values_regex ?? {})) {
            if (!k.trim()) {
              issues.push({
                path: `${reqPath}.query.key_values_regex`,
                message: 'Regex query matcher key cannot be empty',
              });
            }
            if (!pattern.trim()) {
              issues.push({
                path: `${reqPath}.query.key_values_regex.${k}`,
                message: 'Regex pattern cannot be empty',
              });
            } else if (!isValidRegex(pattern.trim())) {
              issues.push({
                path: `${reqPath}.query.key_values_regex.${k}`,
                message: 'Invalid regex pattern',
              });
            }
          }
        }

        if (req.headers) {
          const hasHeaders =
            (req.headers.require_present ?? []).some((v) => !!v.trim()) ||
            (req.headers.deny_present ?? []).some((v) => !!v.trim()) ||
            Object.keys(req.headers.exact ?? {}).length > 0 ||
            Object.keys(req.headers.regex ?? {}).length > 0;
          if (!hasHeaders) {
            issues.push({
              path: `${reqPath}.headers`,
              message: 'Header matcher cannot be empty',
            });
          }
          for (const [k, vals] of Object.entries(req.headers.exact ?? {})) {
            if (!k.trim()) {
              issues.push({
                path: `${reqPath}.headers.exact`,
                message: 'Exact header matcher key cannot be empty',
              });
            }
            if (!vals.length || !vals.some((v) => !!v.trim())) {
              issues.push({
                path: `${reqPath}.headers.exact.${k}`,
                message: 'Exact header matcher values cannot be empty',
              });
            }
          }
          for (const [k, pattern] of Object.entries(req.headers.regex ?? {})) {
            if (!k.trim()) {
              issues.push({
                path: `${reqPath}.headers.regex`,
                message: 'Regex header matcher key cannot be empty',
              });
            }
            if (!pattern.trim()) {
              issues.push({
                path: `${reqPath}.headers.regex.${k}`,
                message: 'Regex header pattern cannot be empty',
              });
            } else if (!isValidRegex(pattern.trim())) {
              issues.push({
                path: `${reqPath}.headers.regex.${k}`,
                message: 'Invalid regex',
              });
            }
          }
        }
      }

      if (tls.http.response?.headers) {
        const headers = tls.http.response.headers;
        const hasHeaders =
          (headers.require_present ?? []).some((v) => !!v.trim()) ||
          (headers.deny_present ?? []).some((v) => !!v.trim()) ||
          Object.keys(headers.exact ?? {}).length > 0 ||
          Object.keys(headers.regex ?? {}).length > 0;
        if (!hasHeaders) {
          issues.push({
            path: `${tlsPath}.http.response.headers`,
            message: 'Response header matcher cannot be empty',
          });
        }
        for (const [k, pattern] of Object.entries(headers.regex ?? {})) {
          if (!k.trim()) {
            issues.push({
              path: `${tlsPath}.http.response.headers.regex`,
              message: 'Regex header matcher key cannot be empty',
            });
          }
          if (pattern.trim() && !isValidRegex(pattern.trim())) {
            issues.push({
              path: `${tlsPath}.http.response.headers.regex.${k}`,
              message: 'Invalid regex',
            });
          }
        }
      }
    }
  }

  return issues;
}

