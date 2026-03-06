import React from 'react';

import type { RuleEditorContextProps } from './ruleEditorTypes';
import { RuleMatchDestinationSection } from './RuleMatchDestinationSection';
import { RuleMatchIcmpSection } from './RuleMatchIcmpSection';
import { RuleMatchPortsSection } from './RuleMatchPortsSection';
import { RuleMatchProtocolDnsSection } from './RuleMatchProtocolDnsSection';

export const RuleMatchCriteriaSection: React.FC<RuleEditorContextProps> = ({
  ...context
}) => (
  <>
    <RuleMatchProtocolDnsSection {...context} />
    <RuleMatchDestinationSection {...context} />
    <RuleMatchPortsSection {...context} />
    <RuleMatchIcmpSection {...context} />
  </>
);
