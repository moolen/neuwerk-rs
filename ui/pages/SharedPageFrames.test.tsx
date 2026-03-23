import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Dashboard } from './Dashboard';
import { DNSCachePage } from './DNSCachePage';
import { PoliciesPage } from './PoliciesPage';
import { ServiceAccountsPage } from './ServiceAccountsPage';
import { useDashboardStats } from './dashboard/useDashboardStats';
import { useDNSCachePage } from './dns-cache/useDNSCachePage';
import { usePolicyBuilder } from './policies/usePolicyBuilder';
import { useServiceAccountsPage } from './service-accounts/useServiceAccountsPage';
import { createEmptyPolicyRequest } from '../utils/policyModel';

vi.mock('./dashboard/useDashboardStats', () => ({
  useDashboardStats: vi.fn(),
}));

vi.mock('./dns-cache/useDNSCachePage', () => ({
  useDNSCachePage: vi.fn(),
}));

vi.mock('./policies/usePolicyBuilder', () => ({
  usePolicyBuilder: vi.fn(),
}));

vi.mock('./service-accounts/useServiceAccountsPage', () => ({
  useServiceAccountsPage: vi.fn(),
}));

vi.mock('./dns-cache/components/DNSCacheControls', () => ({
  DNSCacheControls: () => <div>DNS controls</div>,
}));

vi.mock('./dns-cache/components/DNSCacheTable', () => ({
  DNSCacheTable: () => <div>DNS table</div>,
}));

vi.mock('./dashboard/components/DashboardStatsView', () => ({
  DashboardStatsView: () => <div>Dashboard stats view</div>,
}));

vi.mock('./policies/components/PolicyEditorActions', () => ({
  PolicyEditorActions: () => <div>Policy editor actions</div>,
}));

vi.mock('./policies/components/PolicyEditorCard', () => ({
  PolicyEditorCard: () => <div>Policy editor card</div>,
}));

vi.mock('./policies/components/PolicySnapshotsPanel', () => ({
  PolicySnapshotsPanel: () => <div>Policy snapshots</div>,
}));

vi.mock('../components/service-accounts/CreateServiceAccountModal', () => ({
  CreateServiceAccountModal: () => <div>Create account modal</div>,
}));

vi.mock('../components/service-accounts/EditServiceAccountModal', () => ({
  EditServiceAccountModal: () => <div>Edit account modal</div>,
}));

vi.mock('../components/service-accounts/ServiceAccountTable', () => ({
  ServiceAccountTable: () => <div>Accounts table</div>,
}));

vi.mock('../components/service-accounts/TokenRevealDialog', () => ({
  TokenRevealDialog: () => <div>Token reveal</div>,
}));

vi.mock('./service-accounts/components/CreateTokenModal', () => ({
  CreateTokenModal: () => <div>Create token modal</div>,
}));

vi.mock('./service-accounts/components/ServiceAccountTokensPanel', () => ({
  ServiceAccountTokensPanel: () => <div>Tokens panel</div>,
}));

describe('shared page frames', () => {
  beforeEach(() => {
    vi.mocked(useDashboardStats).mockReturnValue({
      stats: {} as never,
      error: null,
      loading: false,
    });

    vi.mocked(useDNSCachePage).mockReturnValue({
      entries: [{ hostname: 'neuwerk.local', ips: ['10.0.0.2'], last_seen: 1_711_065_600 }],
      filteredEntries: [{ hostname: 'neuwerk.local', ips: ['10.0.0.2'], last_seen: 1_711_065_600 }],
      loading: false,
      error: null,
      searchTerm: '',
      setSearchTerm: () => {},
      refresh: async () => {},
    });

    vi.mocked(useServiceAccountsPage).mockReturnValue({
      serviceAccounts: [],
      loading: false,
      error: null,
      showCreateModal: false,
      setShowCreateModal: () => {},
      showEditModal: false,
      editingAccount: null,
      showTokenDialog: false,
      createdToken: null,
      closeTokenDialog: () => {},
      selectedAccount: null,
      tokens: [],
      tokenLoading: false,
      tokenError: null,
      showTokenModal: false,
      setShowTokenModal: () => {},
      loadTokens: async () => {},
      handleCreateSubmit: async () => {},
      handleEditSubmit: async () => {},
      handleDisableAccount: async () => {},
      handleOpenEditModal: () => {},
      handleCloseEditModal: () => {},
      handleCreateToken: async () => {},
      handleRevokeToken: async () => {},
    });

    vi.mocked(usePolicyBuilder).mockReturnValue({
      state: {
        policies: [],
        integrations: [],
        selectedId: null,
        loading: false,
        error: null,
        draft: createEmptyPolicyRequest(),
        editorMode: 'create',
        editorTargetId: null,
        saving: false,
        editorError: null,
        validationIssues: [],
      },
      actions: {
        loadAll: async () => {},
        loadEditorForPolicy: async () => {},
        handleCreate: () => {},
        handleDelete: async () => {},
        handleSave: async () => {},
        updateDraft: () => {},
        setDraft: () => createEmptyPolicyRequest(),
        addGroup: () => {},
        duplicateGroup: () => {},
        moveGroup: () => {},
        deleteGroup: () => {},
        addRule: () => {},
        duplicateRule: () => {},
        moveRule: () => {},
        deleteRule: () => {},
      },
    });
  });

  it('renders the DNS Cache page inside the shared page frame', () => {
    const html = renderToStaticMarkup(<DNSCachePage />);

    expect(html).toContain('DNS Cache');
    expect(html).toContain('Hostname to IP mappings observed by Neuwerk');
    expect(html).toContain('DNS controls');
    expect(html).toContain('DNS table');
    expect(html).toContain('lg:flex-row');
  });

  it('renders the Dashboard page inside the shared page frame with refresh cadence', () => {
    const html = renderToStaticMarkup(<Dashboard />);

    expect(html).toContain('Dashboard');
    expect(html).toContain('Cluster dataplane, DNS, and control-plane health at a glance.');
    expect(html).toContain('Updated every 5s');
    expect(html).toContain('Dashboard stats view');
    expect(html).toContain('lg:flex-row');
  });

  it('renders the Service Accounts page inside the shared page frame with actions', () => {
    const html = renderToStaticMarkup(<ServiceAccountsPage />);

    expect(html).toContain('Service Accounts');
    expect(html).toContain('Create service accounts and mint JWTs for API access.');
    expect(html).toContain('Create Service Account');
    expect(html).toContain('Accounts table');
    expect(html).toContain('lg:flex-row');
  });

  it('renders the Policies page inside the shared page frame with actions', () => {
    const html = renderToStaticMarkup(<PoliciesPage />);

    expect(html).toContain('Policies');
    expect(html).toContain('Form-driven policy builder with live validation.');
    expect(html).toContain('Refresh');
    expect(html).toContain('New Policy');
    expect(html).toContain('Policy snapshots');
    expect(html).toContain('Policy editor card');
    expect(html).toContain('xl:grid-cols-[minmax(16rem,20rem)_minmax(0,1fr)]');
    expect(html).toContain('lg:flex-row');
  });
});
