import React from 'react';

import type { PolicyTlsMatch } from '../../../types';
import type { UpdateDraft } from './formTypes';
import { mutateRuleTls } from './ruleTlsDraft';
import { TlsNameMatchEditor } from './TlsNameMatchEditor';

interface TlsMetadataNameMatchersSectionProps {
  groupIndex: number;
  ruleIndex: number;
  tls: PolicyTlsMatch;
  updateDraft: UpdateDraft;
}

export const TlsMetadataNameMatchersSection: React.FC<TlsMetadataNameMatchersSectionProps> = ({
  groupIndex,
  ruleIndex,
  tls,
  updateDraft,
}) => (
  <>
    <TlsNameMatchEditor
      label="SNI matcher"
      value={tls.sni}
      onChange={(nextValue) =>
        mutateRuleTls(updateDraft, groupIndex, ruleIndex, (nextTls) => {
          nextTls.sni = nextValue;
        })
      }
    />
    <TlsNameMatchEditor
      label="Server SAN matcher"
      value={tls.server_san}
      onChange={(nextValue) =>
        mutateRuleTls(updateDraft, groupIndex, ruleIndex, (nextTls) => {
          nextTls.server_san = nextValue;
        })
      }
    />
    <TlsNameMatchEditor
      label="Server CN matcher"
      value={tls.server_cn}
      onChange={(nextValue) =>
        mutateRuleTls(updateDraft, groupIndex, ruleIndex, (nextTls) => {
          nextTls.server_cn = nextValue;
        })
      }
    />
  </>
);
