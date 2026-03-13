import React from 'react';

import type { ServiceAccountRole } from '../../types';
import { serviceAccountRoleLabel, serviceAccountRoleStyle } from './helpers';

interface ServiceAccountRoleBadgeProps {
  role: ServiceAccountRole;
}

export const ServiceAccountRoleBadge: React.FC<ServiceAccountRoleBadgeProps> = ({ role }) => (
  <span
    className="inline-flex items-center rounded-full px-2 py-1 text-xs font-medium"
    style={serviceAccountRoleStyle(role)}
  >
    {serviceAccountRoleLabel(role)}
  </span>
);
