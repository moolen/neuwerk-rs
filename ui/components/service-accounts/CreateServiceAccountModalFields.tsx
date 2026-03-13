import React from 'react';
import { SERVICE_ACCOUNT_ROLES } from '../../types';
import type { ServiceAccountRole } from '../../types';

interface CreateServiceAccountModalFieldsProps {
  name: string;
  description: string;
  role: ServiceAccountRole;
  loading: boolean;
  onNameChange: (value: string) => void;
  onDescriptionChange: (value: string) => void;
  onRoleChange: (value: ServiceAccountRole) => void;
}

export const CreateServiceAccountModalFields: React.FC<CreateServiceAccountModalFieldsProps> = ({
  name,
  description,
  role,
  loading,
  onNameChange,
  onDescriptionChange,
  onRoleChange,
}) => (
  <div className="space-y-4 mb-6">
    <div>
      <label htmlFor="name" className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        Name
      </label>
      <input
        id="name"
        type="text"
        value={name}
        onChange={(e) => onNameChange(e.target.value)}
        disabled={loading}
        placeholder="ci-deployer"
        className="w-full px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
        style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
      />
    </div>

    <div>
      <label htmlFor="description" className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        Description (optional)
      </label>
      <textarea
        id="description"
        value={description}
        onChange={(e) => onDescriptionChange(e.target.value)}
        disabled={loading}
        rows={3}
        placeholder="Used by CI pipeline"
        className="w-full px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
        style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
      />
    </div>

    <div>
      <label
        htmlFor="role"
        className="block text-sm font-medium mb-1"
        style={{ color: 'var(--text-secondary)' }}
      >
        Role
      </label>
      <select
        id="role"
        value={role}
        onChange={(e) => onRoleChange(e.target.value as ServiceAccountRole)}
        disabled={loading}
        className="w-full px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      >
        {SERVICE_ACCOUNT_ROLES.map((value) => (
          <option key={value} value={value}>
            {value === 'readonly' ? 'Readonly' : 'Admin'}
          </option>
        ))}
      </select>
      <p className="mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
        {role === 'readonly'
          ? 'Readonly accounts can inspect API resources but cannot change policies or settings.'
          : 'Admin accounts can create, update, and delete managed resources.'}
      </p>
    </div>
  </div>
);
