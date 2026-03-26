import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { PolicySourceGroup, PolicySourceGroupTelemetry } from '../../../types';
import { PolicySourceGroupsTable } from './PolicySourceGroupsTable';

function buildGroup(overrides: Partial<PolicySourceGroup> = {}): PolicySourceGroup {
  return {
    id: 'apps',
    priority: 0,
    default_action: 'allow',
    sources: {
      cidrs: ['10.0.0.0/24'],
      ips: ['192.168.1.10'],
      kubernetes: [],
    },
    rules: [
      {
        id: 'rule-1',
        action: 'allow',
        match: {
          proto: 'tcp',
          dst_ports: ['443'],
          dst_cidrs: [],
          dst_ips: [],
          src_ports: [],
          icmp_types: [],
          icmp_codes: [],
        },
      },
    ],
    ...overrides,
  };
}

describe('PolicySourceGroupsTable', () => {
  it('renders the source-group table headers and row summaries', () => {
    const telemetryBySourceGroupId: Record<string, PolicySourceGroupTelemetry> = {
      apps: {
        source_group_id: 'apps',
        current_24h_hits: 120,
        previous_24h_hits: 100,
      },
    };
    const html = renderToStaticMarkup(
      <PolicySourceGroupsTable
        groups={[buildGroup()]}
        activeSourceGroupId={null}
        telemetryBySourceGroupId={telemetryBySourceGroupId}
        onCreateGroup={() => undefined}
        onDeleteGroup={() => undefined}
        onMoveGroup={() => undefined}
        onSelectGroup={() => undefined}
      />
    );

    expect(html).toContain('Source Identity');
    expect(html).toContain('L3/L4/DNS/DPI Rules');
    expect(html).toContain('Action');
    expect(html).toContain('Hits');
    expect(html).toContain('apps');
    expect(html).toContain('10.0.0.0/24');
    expect(html).toContain('192.168.1.10');
    expect(html).toContain('TCP:443');
    expect(html).toContain('Allow');
    expect(html).toContain('120 hits');
    expect(html).toContain('+20%');
  });

  it('renders the empty-state call to create the first source group', () => {
    const html = renderToStaticMarkup(
      <PolicySourceGroupsTable
        groups={[]}
        activeSourceGroupId={null}
        onCreateGroup={() => undefined}
        onDeleteGroup={() => undefined}
        onMoveGroup={() => undefined}
        onSelectGroup={() => undefined}
      />
    );

    expect(html).toContain('No source groups configured');
    expect(html).toContain('Add first source group');
  });

  it('renders a partial telemetry warning when cluster aggregation is degraded', () => {
    const html = renderToStaticMarkup(
      <PolicySourceGroupsTable
        groups={[buildGroup()]}
        activeSourceGroupId={null}
        telemetryPartial
        telemetryNodesQueried={3}
        telemetryNodesResponded={2}
        telemetryNodeErrorCount={1}
        onCreateGroup={() => undefined}
        onDeleteGroup={() => undefined}
        onMoveGroup={() => undefined}
        onSelectGroup={() => undefined}
      />
    );

    expect(html).toContain('Telemetry is partial');
    expect(html).toContain('2 of 3 nodes responded');
    expect(html).toContain('1 node error');
  });
});
