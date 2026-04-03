import React from 'react';

import type { RuleEditorContextProps } from './ruleEditorTypes';
import { RuleMatchDnsHostnameField } from './RuleMatchDnsHostnameField';
import { RuleMatchProtocolField } from './RuleMatchProtocolField';

export const RuleMatchProtocolDnsSection: React.FC<RuleEditorContextProps> = ({
  ...context
}) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
    <RuleMatchProtocolField {...context} />
    <RuleMatchDnsHostnameField {...context} />
  </div>
);
