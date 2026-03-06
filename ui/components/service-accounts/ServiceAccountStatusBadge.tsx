import React from 'react';
import type { ServiceAccount } from '../../types';
import { serviceAccountStatusLabel, serviceAccountStatusStyle } from './helpers';

interface ServiceAccountStatusBadgeProps {
  status: ServiceAccount['status'];
}

export const ServiceAccountStatusBadge: React.FC<ServiceAccountStatusBadgeProps> = ({ status }) => (
  <span className="inline-flex px-2 py-1 text-xs font-medium rounded" style={serviceAccountStatusStyle(status)}>
    {serviceAccountStatusLabel(status)}
  </span>
);
