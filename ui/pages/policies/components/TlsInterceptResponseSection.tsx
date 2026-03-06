import React from 'react';

import { KeyValueEditor } from '../../../components/KeyValueEditor';
import type { PolicyTlsMatch } from '../../../types';
import { emptyTlsHeaders, textToList } from '../helpers';
import type { UpdateDraft } from './formTypes';
import { StringListMapEditor } from './StringListMapEditor';

interface TlsInterceptResponseSectionProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsInterceptResponseSection: React.FC<TlsInterceptResponseSectionProps> = ({
  groupIndex,
  ruleIndex,
  tls,
  updateDraft,
}) => {
  if (!tls.http?.response) {
    return null;
  }

  return (
    <div className="rounded p-3 space-y-3" style={{ border: '1px dashed var(--border-subtle)' }}>
      <h6 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
        HTTP response headers
      </h6>
      <input
        type="text"
        value={(tls.http.response.headers?.require_present ?? []).join(', ')}
        onChange={(e) =>
          updateDraft((next) => {
            const response = next.policy.source_groups[groupIndex].rules[ruleIndex].match.tls?.http
              ?.response;
            if (!response) return;
            response.headers = response.headers ?? emptyTlsHeaders();
            response.headers.require_present = textToList(e.target.value);
          })
        }
        placeholder="require_present"
        className="w-full px-2 py-1 rounded text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      />
      <input
        type="text"
        value={(tls.http.response.headers?.deny_present ?? []).join(', ')}
        onChange={(e) =>
          updateDraft((next) => {
            const response = next.policy.source_groups[groupIndex].rules[ruleIndex].match.tls?.http
              ?.response;
            if (!response) return;
            response.headers = response.headers ?? emptyTlsHeaders();
            response.headers.deny_present = textToList(e.target.value);
          })
        }
        placeholder="deny_present"
        className="w-full px-2 py-1 rounded text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      />

      <StringListMapEditor
        label="Headers exact"
        value={tls.http.response.headers?.exact ?? {}}
        onChange={(nextMap) =>
          updateDraft((next) => {
            const response = next.policy.source_groups[groupIndex].rules[ruleIndex].match.tls?.http
              ?.response;
            if (!response) return;
            response.headers = response.headers ?? emptyTlsHeaders();
            response.headers.exact = nextMap;
          })
        }
        keyPlaceholder="header"
        valuePlaceholder="v1, v2"
      />

      <KeyValueEditor
        label="Headers regex"
        value={tls.http.response.headers?.regex ?? {}}
        onChange={(nextMap) =>
          updateDraft((next) => {
            const response = next.policy.source_groups[groupIndex].rules[ruleIndex].match.tls?.http
              ?.response;
            if (!response) return;
            response.headers = response.headers ?? emptyTlsHeaders();
            response.headers.regex = nextMap;
          })
        }
        fieldPrefix={`group.${groupIndex}.rule.${ruleIndex}.tls.http.response.headers.regex`}
        errors={{}}
        keyPlaceholder="header"
        valuePlaceholder="regex"
      />
    </div>
  );
};
