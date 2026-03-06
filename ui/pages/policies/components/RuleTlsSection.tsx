import React from 'react';

import { TlsInterceptHttpSection } from './TlsInterceptHttpSection';
import { TlsMetadataSection } from './TlsMetadataSection';
import { RuleTlsHeader } from './RuleTlsHeader';
import { RuleTlsModeControls } from './RuleTlsModeControls';
import type { RuleEditorContextProps } from './ruleEditorTypes';
import {
  setRuleTls13Uninspectable,
  setRuleTlsMode,
  toggleRuleTls,
} from './ruleTlsDraft';

export const RuleTlsSection: React.FC<RuleEditorContextProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
}) => {
  const tls = rule.match.tls;
  const tlsMode = tls?.mode ?? 'metadata';
  const tls13Uninspectable = tls?.tls13_uninspectable ?? 'deny';

  return (
    <div
      className="rounded p-3 space-y-3"
      style={{ border: '1px solid var(--border-subtle)', background: 'var(--bg)' }}
    >
      <RuleTlsHeader
        enabled={Boolean(tls)}
        onToggle={() => {
          toggleRuleTls(updateDraft, groupIndex, ruleIndex);
        }}
      />

      {tls && (
        <div className="space-y-3">
          <RuleTlsModeControls
            mode={tlsMode}
            tls13Uninspectable={tls13Uninspectable}
            onModeChange={(mode) => {
              setRuleTlsMode(updateDraft, groupIndex, ruleIndex, mode);
            }}
            onTls13UninspectableChange={(value) => {
              setRuleTls13Uninspectable(updateDraft, groupIndex, ruleIndex, value);
            }}
          />

          {tlsMode === 'metadata' && (
            <TlsMetadataSection
              groupIndex={groupIndex}
              ruleIndex={ruleIndex}
              tls={tls}
              updateDraft={updateDraft}
            />
          )}

          {tlsMode === 'intercept' && (
            <TlsInterceptHttpSection
              groupIndex={groupIndex}
              ruleIndex={ruleIndex}
              tls={tls}
              updateDraft={updateDraft}
            />
          )}
        </div>
      )}
    </div>
  );
};
