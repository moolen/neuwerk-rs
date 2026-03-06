import React from 'react';

import type { PolicyValidationIssue } from '../../../utils/policyValidation';
import { formatIssues } from '../helpers';

interface PolicyEditorMessagesProps {
  validationIssues: PolicyValidationIssue[];
  editorError: string | null;
}

export const PolicyEditorMessages: React.FC<PolicyEditorMessagesProps> = ({
  validationIssues,
  editorError,
}) => (
  <>
    {validationIssues.length > 0 && (
      <div
        className="rounded-lg p-4"
        style={{ background: 'var(--amber-bg)', border: '1px solid var(--amber-border)', color: 'var(--amber)' }}
      >
        <div className="font-semibold text-sm mb-2">Validation issues ({validationIssues.length})</div>
        <div className="text-xs space-y-1 max-h-48 overflow-auto">
          {formatIssues(validationIssues).map((line, idx) => (
            <div key={`issue-${idx}`}>{line}</div>
          ))}
        </div>
      </div>
    )}

    {editorError && (
      <div
        className="rounded-lg p-4"
        style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}
      >
        {editorError}
      </div>
    )}
  </>
);
