import React from 'react';

import { KeyValueEditor } from '../../../components/KeyValueEditor';
import type { PolicyTlsMatch } from '../../../types';
import { textToList } from '../helpers';
import type { UpdateDraft } from './formTypes';
import { StringListMapEditor } from './StringListMapEditor';
import {
  ensureTlsRequestQuery,
  mutateTlsInterceptRequest,
} from './tlsInterceptRequestDraft';

interface TlsInterceptRequestQuerySectionProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsInterceptRequestQuerySection: React.FC<TlsInterceptRequestQuerySectionProps> = ({
  groupIndex,
  ruleIndex,
  tls,
  updateDraft,
}) => (
  <>
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        Query keys_present
      </label>
      <input
        type="text"
        value={(tls.http?.request?.query?.keys_present ?? []).join(', ')}
        onChange={(e) =>
          mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
            ensureTlsRequestQuery(request).keys_present = textToList(e.target.value);
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

    <StringListMapEditor
      label="Query key_values_exact"
      value={tls.http?.request?.query?.key_values_exact ?? {}}
      onChange={(nextMap) =>
        mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
          ensureTlsRequestQuery(request).key_values_exact = nextMap;
        })
      }
      keyPlaceholder="query key"
      valuePlaceholder="v1, v2"
    />

    <KeyValueEditor
      label="Query key_values_regex"
      value={tls.http?.request?.query?.key_values_regex ?? {}}
      onChange={(nextMap) =>
        mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
          ensureTlsRequestQuery(request).key_values_regex = nextMap;
        })
      }
      fieldPrefix={`group.${groupIndex}.rule.${ruleIndex}.tls.http.query.regex`}
      errors={{}}
      keyPlaceholder="query key"
      valuePlaceholder="regex"
    />
  </>
);
