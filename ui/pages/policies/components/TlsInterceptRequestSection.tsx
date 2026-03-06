import React from 'react';

import type { PolicyTlsMatch } from '../../../types';
import type { UpdateDraft } from './formTypes';
import { TlsInterceptRequestHeadersSection } from './TlsInterceptRequestHeadersSection';
import { TlsInterceptRequestMethodsField } from './TlsInterceptRequestMethodsField';
import { TlsInterceptRequestPathSection } from './TlsInterceptRequestPathSection';
import { TlsInterceptRequestQuerySection } from './TlsInterceptRequestQuerySection';
import { TlsNameMatchEditor } from './TlsNameMatchEditor';
import { mutateTlsInterceptRequest } from './tlsInterceptRequestDraft';

interface TlsInterceptRequestSectionProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsInterceptRequestSection: React.FC<TlsInterceptRequestSectionProps> = ({
  groupIndex,
  ruleIndex,
  tls,
  updateDraft,
}) => {
  if (!tls.http?.request) {
    return null;
  }

  return (
    <div className="rounded p-3 space-y-3" style={{ border: '1px dashed var(--border-subtle)' }}>
      <h6 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
        HTTP request
      </h6>
      <TlsNameMatchEditor
        label="Host matcher"
        value={tls.http.request.host}
        onChange={(nextValue) =>
          mutateTlsInterceptRequest(updateDraft, groupIndex, ruleIndex, (request) => {
            request.host = nextValue;
          })
        }
      />

      <TlsInterceptRequestMethodsField
        groupIndex={groupIndex}
        ruleIndex={ruleIndex}
        tls={tls}
        updateDraft={updateDraft}
      />

      <TlsInterceptRequestPathSection
        groupIndex={groupIndex}
        ruleIndex={ruleIndex}
        tls={tls}
        updateDraft={updateDraft}
      />

      <TlsInterceptRequestQuerySection
        groupIndex={groupIndex}
        ruleIndex={ruleIndex}
        tls={tls}
        updateDraft={updateDraft}
      />

      <TlsInterceptRequestHeadersSection
        groupIndex={groupIndex}
        ruleIndex={ruleIndex}
        tls={tls}
        updateDraft={updateDraft}
      />
    </div>
  );
};
