import { describe, expect, it } from 'vitest';

import { createEmptyIntegrationForm } from './types';
import { validateIntegrationFormForSave } from './formValidation';

describe('validateIntegrationFormForSave', () => {
  it('requires name in create mode', () => {
    const form = createEmptyIntegrationForm();
    const result = validateIntegrationFormForSave(form, 'create');
    expect(result.error).toBe('name is required');
  });

  it('requires URL/CA/token in edit mode', () => {
    const form = createEmptyIntegrationForm();
    form.name = 'k8s-prod';
    const result = validateIntegrationFormForSave(form, 'edit');
    expect(result.error).toBe('kube-apiserver URL is required');
  });

  it('returns trimmed values when valid', () => {
    const form = createEmptyIntegrationForm();
    form.name = '  k8s-prod  ';
    form.apiServerUrl = '  https://10.0.0.1:6443 ';
    form.caCertPem = '  CERT ';
    form.serviceAccountToken = '  TOKEN ';

    const result = validateIntegrationFormForSave(form, 'create');
    expect(result.value).toEqual({
      name: 'k8s-prod',
      apiServerUrl: 'https://10.0.0.1:6443',
      caCertPem: 'CERT',
      serviceAccountToken: 'TOKEN',
    });
  });
});
