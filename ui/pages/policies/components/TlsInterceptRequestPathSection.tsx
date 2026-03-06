import React from 'react';

import type { PolicyTlsMatch } from '../../../types';
import { listToText, textToList } from '../helpers';
import type { UpdateDraft } from './formTypes';
import {
  ensureTlsRequestPath,
  mutateTlsInterceptRequest,
} from './tlsInterceptRequestDraft';

interface TlsInterceptRequestPathSectionProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsInterceptRequestPathSection: React.FC<TlsInterceptRequestPathSectionProps> = ({
  groupIndex,
  ruleIndex,
  tls,
  updateDraft,
}) => (
  <>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <div>
        <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
          Path exact
        </label>
        <textarea
          rows={2}
          value={listToText(tls.http?.request?.path?.exact ?? [])}
          onChange={(e) =>
            mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
              ensureTlsRequestPath(request).exact = textToList(e.target.value);
            })
          }
          className="w-full px-2 py-1 rounded text-sm"
          style={{
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text)',
          }}
        />
      </div>
      <div>
        <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
          Path prefix
        </label>
        <textarea
          rows={2}
          value={listToText(tls.http?.request?.path?.prefix ?? [])}
          onChange={(e) =>
            mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
              ensureTlsRequestPath(request).prefix = textToList(e.target.value);
            })
          }
          className="w-full px-2 py-1 rounded text-sm"
          style={{
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text)',
          }}
        />
      </div>
    </div>

    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        Path regex
      </label>
      <input
        type="text"
        value={tls.http?.request?.path?.regex ?? ''}
        onChange={(e) =>
          mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
            ensureTlsRequestPath(request).regex = e.target.value;
          })
        }
        className="w-full px-2 py-1 rounded text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      />
    </div>
  </>
);
