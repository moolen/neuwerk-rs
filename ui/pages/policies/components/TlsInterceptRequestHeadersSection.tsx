import React from 'react';

import { KeyValueEditor } from '../../../components/KeyValueEditor';
import type { PolicyTlsMatch } from '../../../types';
import { textToList } from '../helpers';
import type { UpdateDraft } from './formTypes';
import { StringListMapEditor } from './StringListMapEditor';
import {
  ensureTlsRequestHeaders,
  mutateTlsInterceptRequest,
} from './tlsInterceptRequestDraft';

interface TlsInterceptRequestHeadersSectionProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsInterceptRequestHeadersSection: React.FC<
  TlsInterceptRequestHeadersSectionProps
> = ({ groupIndex, ruleIndex, tls, updateDraft }) => (
  <div className="space-y-3">
    <div className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
      Request headers
    </div>
    <input
      type="text"
      value={(tls.http?.request?.headers?.require_present ?? []).join(', ')}
      onChange={(e) =>
        mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
          ensureTlsRequestHeaders(request).require_present = textToList(e.target.value);
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
      value={(tls.http?.request?.headers?.deny_present ?? []).join(', ')}
      onChange={(e) =>
        mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
          ensureTlsRequestHeaders(request).deny_present = textToList(e.target.value);
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
      value={tls.http?.request?.headers?.exact ?? {}}
      onChange={(nextMap) =>
        mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
          ensureTlsRequestHeaders(request).exact = nextMap;
        })
      }
      keyPlaceholder="header"
      valuePlaceholder="v1, v2"
    />

    <KeyValueEditor
      label="Headers regex"
      value={tls.http?.request?.headers?.regex ?? {}}
      onChange={(nextMap) =>
        mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
          ensureTlsRequestHeaders(request).regex = nextMap;
        })
      }
      fieldPrefix={`group.${groupIndex}.rule.${ruleIndex}.tls.http.request.headers.regex`}
      errors={{}}
      keyPlaceholder="header"
      valuePlaceholder="regex"
    />
  </div>
);
