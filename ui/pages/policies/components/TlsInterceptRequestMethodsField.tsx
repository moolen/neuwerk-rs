import React from 'react';

import type { PolicyTlsMatch } from '../../../types';
import { textToList } from '../helpers';
import type { UpdateDraft } from './formTypes';
import { mutateTlsInterceptRequest } from './tlsInterceptRequestDraft';

interface TlsInterceptRequestMethodsFieldProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsInterceptRequestMethodsField: React.FC<TlsInterceptRequestMethodsFieldProps> = ({
  groupIndex,
  ruleIndex,
  tls,
  updateDraft,
}) => (
  <div>
    <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
      Methods
    </label>
    <input
      type="text"
      value={(tls.http?.request?.methods ?? []).join(', ')}
      onChange={(e) =>
        mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
          request.methods = textToList(e.target.value).map((method) => method.toUpperCase());
        })
      }
      placeholder="GET, POST"
      className="w-full px-2 py-1 rounded text-sm"
      style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        color: 'var(--text)',
      }}
    />
  </div>
);
