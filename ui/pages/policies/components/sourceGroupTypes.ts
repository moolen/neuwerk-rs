import type { IntegrationView, PolicySourceGroup } from '../../../types';
import type { UpdateDraft } from './formTypes';

export interface SourceGroupContextProps {
  group: PolicySourceGroup;
  groupIndex: number;
  integrations: IntegrationView[];
  updateDraft: UpdateDraft;
}

export interface SourceGroupActionProps {
  duplicateGroup: (groupIndex: number) => void;
  moveGroup: (groupIndex: number, direction: -1 | 1) => void;
  deleteGroup: (groupIndex: number) => void;
  addRule: (groupIndex: number) => void;
  duplicateRule: (groupIndex: number, ruleIndex: number) => void;
  moveRule: (groupIndex: number, ruleIndex: number, direction: -1 | 1) => void;
  deleteRule: (groupIndex: number, ruleIndex: number) => void;
}
