import React from 'react';

import type { PolicyTlsMatch } from '../../../types';
import type { UpdateDraft } from './formTypes';
import { mutateRuleTls } from './ruleTlsDraft';
import { TlsMetadataFingerprintField } from './TlsMetadataFingerprintField';
import { TlsMetadataNameMatchersSection } from './TlsMetadataNameMatchersSection';
import { TlsMetadataServerDnField } from './TlsMetadataServerDnField';
import { TlsMetadataTrustAnchorsSection } from './TlsMetadataTrustAnchorsSection';

interface TlsMetadataSectionProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsMetadataSection: React.FC<TlsMetadataSectionProps> = ({
  groupIndex,
  ruleIndex,
  tls,
  updateDraft,
}) => (
  <div className="space-y-3">
    <TlsMetadataNameMatchersSection
      groupIndex={groupIndex}
      ruleIndex={ruleIndex}
      tls={tls}
      updateDraft={updateDraft}
    />
    <TlsMetadataServerDnField
      value={tls.server_dn ?? ''}
      onChange={(nextValue) =>
        mutateRuleTls(updateDraft, groupIndex, ruleIndex, (nextTls) => {
          if (!nextValue.trim()) {
            delete nextTls.server_dn;
          } else {
            nextTls.server_dn = nextValue;
          }
        })
      }
    />
    <TlsMetadataFingerprintField
      value={tls.fingerprint_sha256 ?? []}
      onChange={(nextValue) =>
        mutateRuleTls(updateDraft, groupIndex, ruleIndex, (nextTls) => {
          nextTls.fingerprint_sha256 = nextValue;
        })
      }
    />
    <TlsMetadataTrustAnchorsSection
      trustAnchors={tls.trust_anchors_pem ?? []}
      onAdd={() =>
        mutateRuleTls(updateDraft, groupIndex, ruleIndex, (nextTls) => {
          nextTls.trust_anchors_pem = [...(nextTls.trust_anchors_pem ?? []), ''];
        })
      }
      onChange={(pemIndex, nextPem) =>
        mutateRuleTls(updateDraft, groupIndex, ruleIndex, (nextTls) => {
          nextTls.trust_anchors_pem[pemIndex] = nextPem;
        })
      }
      onRemove={(pemIndex) =>
        mutateRuleTls(updateDraft, groupIndex, ruleIndex, (nextTls) => {
          nextTls.trust_anchors_pem.splice(pemIndex, 1);
        })
      }
    />
  </div>
);
