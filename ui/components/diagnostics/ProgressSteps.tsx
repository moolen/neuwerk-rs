import React, { useEffect, useRef } from 'react';
import { Loader2, CheckCircle2, XCircle, Circle } from 'lucide-react';
import type { ProgressStep } from '../../types';

interface ProgressStepsProps {
  steps: ProgressStep[];
}

export const ProgressSteps: React.FC<ProgressStepsProps> = ({ steps }) => {
  const lastStepRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to latest step
  useEffect(() => {
    if (lastStepRef.current) {
      lastStepRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [steps.length]);

  const getStatusIcon = (status: ProgressStep['status']) => {
    switch (status) {
      case 'in-progress':
        return <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />;
      case 'complete':
        return <CheckCircle2 className="w-5 h-5 text-green-500" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-500" />;
      default:
        return <Circle className="w-5 h-5 text-slate-400" />;
    }
  };

  const getStatusColor = (status: ProgressStep['status']) => {
    switch (status) {
      case 'in-progress': return 'text-blue-500';
      case 'complete': return 'text-green-500';
      case 'failed': return 'text-red-500';
      default: return 'text-slate-400';
    }
  };

  const formatPhase = (phase: string) => {
    return phase.charAt(0).toUpperCase() + phase.slice(1);
  };

  return (
    <div className="space-y-2">
      {steps.map((step, index) => (
        <div
          key={index}
          ref={index === steps.length - 1 ? lastStepRef : null}
          className="flex items-center gap-3 p-3 bg-slate-800 border border-slate-700 rounded"
        >
          {getStatusIcon(step.status)}
          <div className="flex-1">
            <div className="text-white font-medium">
              {formatPhase(step.phase)}
              {step.node && <span className="text-slate-400 ml-2">(node: {step.node})</span>}
            </div>
            <div className={`text-sm ${getStatusColor(step.status)}`}>
              {step.status === 'in-progress' && 'In progress...'}
              {step.status === 'complete' && 'Complete'}
              {step.status === 'failed' && 'Failed'}
              {step.status === 'pending' && 'Pending'}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};
