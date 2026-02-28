export const POLICY_REQUEST_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'Firewall Policy Update',
  description: 'YAML policy update payload sent to the control-plane API.',
  type: 'object',
  additionalProperties: false,
  required: ['mode', 'policy'],
  properties: {
    mode: {
      type: 'string',
      enum: ['disabled', 'enforce', 'audit'],
      description: 'Policy activity mode: disabled, audit passthrough, or enforce.',
      default: 'enforce',
    },
    policy: {
      $ref: '#/definitions/policyConfig',
    },
  },
  definitions: {
    policyConfig: {
      type: 'object',
      additionalProperties: false,
      description: 'Policy rules and source groups.',
      properties: {
        default_policy: {
          type: 'string',
          enum: ['allow', 'deny'],
          description: 'Default action when no rule matches.',
        },
        source_groups: {
          type: 'array',
          description: 'Source groups evaluated in priority order.',
          items: { $ref: '#/definitions/sourceGroup' },
        },
      },
    },
    sourceGroup: {
      type: 'object',
      additionalProperties: false,
      required: ['id', 'sources'],
      properties: {
        id: {
          type: 'string',
          description: 'Stable identifier for the source group.',
        },
        priority: {
          type: 'integer',
          minimum: 0,
          description: 'Lower priority numbers are evaluated first.',
        },
        sources: {
          $ref: '#/definitions/sourceGroupSources',
        },
        rules: {
          type: 'array',
          items: { $ref: '#/definitions/ruleConfig' },
          description: 'Rules applied to traffic originating from this group.',
        },
        default_action: {
          type: 'string',
          enum: ['allow', 'deny'],
          description: 'Fallback action for this source group.',
        },
      },
    },
    sourceGroupSources: {
      type: 'object',
      additionalProperties: false,
      description: 'CIDRs and/or individual IPs for the group.',
      properties: {
        cidrs: {
          type: 'array',
          minItems: 1,
          items: { type: 'string' },
          description: 'IPv4 CIDR ranges (e.g. 10.0.0.0/24).',
        },
        ips: {
          type: 'array',
          minItems: 1,
          items: { type: 'string', format: 'ipv4' },
          description: 'Individual IPv4 addresses.',
        },
      },
      anyOf: [{ required: ['cidrs'] }, { required: ['ips'] }],
    },
    ruleConfig: {
      type: 'object',
      additionalProperties: false,
      required: ['id', 'action', 'match'],
      properties: {
        id: {
          type: 'string',
          description: 'Stable identifier for the rule.',
        },
        priority: {
          type: 'integer',
          minimum: 0,
          description: 'Lower priority numbers are evaluated first.',
        },
        action: {
          type: 'string',
          enum: ['allow', 'deny'],
          description: 'Action applied when the rule matches.',
        },
        mode: {
          type: 'string',
          enum: ['enforce', 'audit'],
          description: 'Audit rules are ignored for enforcement.',
          default: 'enforce',
        },
        match: {
          $ref: '#/definitions/ruleMatch',
        },
      },
    },
    ruleMatch: {
      type: 'object',
      additionalProperties: false,
      description: 'Traffic match criteria.',
      properties: {
        dst_cidrs: {
          type: 'array',
          items: { type: 'string' },
          description: 'Destination IPv4 CIDRs.',
        },
        dst_ips: {
          type: 'array',
          items: { type: 'string', format: 'ipv4' },
          description: 'Destination IPv4 addresses.',
        },
        dns_hostname: {
          type: 'string',
          description: 'Regex matched against DNS hostnames.',
        },
        proto: {
          $ref: '#/definitions/protoValue',
        },
        src_ports: {
          type: 'array',
          items: { $ref: '#/definitions/portSpec' },
          description: 'Source ports (number or range).',
        },
        dst_ports: {
          type: 'array',
          items: { $ref: '#/definitions/portSpec' },
          description: 'Destination ports (number or range).',
        },
        icmp_types: {
          type: 'array',
          items: { type: 'integer', minimum: 0, maximum: 255 },
          description: 'ICMP types to match (requires proto icmp or any).',
        },
        icmp_codes: {
          type: 'array',
          items: { type: 'integer', minimum: 0, maximum: 255 },
          description: 'ICMP codes to match (requires proto icmp or any).',
        },
        tls: {
          $ref: '#/definitions/tlsMatch',
        },
      },
    },
    protoValue: {
      description: 'Protocol name or numeric value.',
      oneOf: [
        {
          type: 'string',
          enum: ['any', 'tcp', 'udp', 'icmp'],
        },
        {
          type: 'integer',
          minimum: 0,
          maximum: 255,
        },
        {
          type: 'string',
          pattern: '^[0-9]+$',
          description: 'Numeric protocol as a string.',
        },
      ],
    },
    portSpec: {
      description: 'Single port (number) or range (e.g. "80-81").',
      oneOf: [
        {
          type: 'integer',
          minimum: 1,
          maximum: 65535,
        },
        {
          type: 'string',
          pattern: '^(\\d{1,5})(\\s*-\\s*\\d{1,5})?$',
        },
      ],
    },
    tlsMatch: {
      type: 'object',
      additionalProperties: false,
      description: 'TLS inspection and verification constraints.',
      properties: {
        sni: { $ref: '#/definitions/tlsNameMatch' },
        server_dn: {
          type: 'string',
          description: 'Legacy alias for tls.server_cn regex match.',
        },
        server_san: { $ref: '#/definitions/tlsNameMatch' },
        server_cn: { $ref: '#/definitions/tlsNameMatch' },
        fingerprint_sha256: {
          type: 'array',
          items: { type: 'string' },
          description: 'SHA-256 fingerprints (hex with optional colons).',
        },
        trust_anchors_pem: {
          type: 'array',
          items: { type: 'string' },
          description: 'PEM-encoded certificate(s) used as trust anchors.',
        },
        tls13_uninspectable: {
          type: 'string',
          enum: ['allow', 'deny'],
          description: 'Action when TLS 1.3 certificates are uninspectable.',
        },
      },
    },
    tlsNameMatch: {
      description: 'Match TLS names by exact list or regex.',
      oneOf: [
        {
          type: 'string',
          description: 'Regex string.',
        },
        {
          type: 'array',
          items: { type: 'string' },
          description: 'Exact match values.',
        },
        {
          type: 'object',
          additionalProperties: false,
          properties: {
            exact: {
              type: 'array',
              items: { type: 'string' },
              description: 'Exact hostnames.',
            },
            regex: {
              type: 'string',
              description: 'Regex string.',
            },
          },
        },
      ],
    },
  },
} as const;
