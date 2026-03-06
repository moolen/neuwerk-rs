import React from 'react';

import type { PolicyTlsMatch } from '../../../types';
import type { UpdateDraft } from './formTypes';
import { TlsInterceptConstraintControls } from './TlsInterceptConstraintControls';
import { TlsInterceptRequestSection } from './TlsInterceptRequestSection';
import { TlsInterceptResponseSection } from './TlsInterceptResponseSection';
import {
  disableTlsInterceptRequest,
  disableTlsInterceptResponse,
  enableTlsInterceptRequest,
  enableTlsInterceptResponse,
} from './tlsInterceptHttpDraft';

interface TlsInterceptHttpSectionProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsInterceptHttpSection: React.FC<TlsInterceptHttpSectionProps> = ({
  groupIndex,
  ruleIndex,
  tls,
  updateDraft,
}) => (
  <div className="space-y-4">
    <TlsInterceptConstraintControls
      label="request constraints"
      onEnable={() =>
        updateDraft((next) => {
          enableTlsInterceptRequest(next, groupIndex, ruleIndex);
        })
      }
      onDisable={() =>
        updateDraft((next) => {
          disableTlsInterceptRequest(next, groupIndex, ruleIndex);
        })
      }
    />

    <TlsInterceptRequestSection
      groupIndex={groupIndex}
      ruleIndex={ruleIndex}
      tls={tls}
      updateDraft={updateDraft}
    />

    <TlsInterceptConstraintControls
      label="response constraints"
      onEnable={() =>
        updateDraft((next) => {
          enableTlsInterceptResponse(next, groupIndex, ruleIndex);
        })
      }
      onDisable={() =>
        updateDraft((next) => {
          disableTlsInterceptResponse(next, groupIndex, ruleIndex);
        })
      }
    />

    <TlsInterceptResponseSection
      groupIndex={groupIndex}
      ruleIndex={ruleIndex}
      tls={tls}
      updateDraft={updateDraft}
    />
  </div>
);
