import { useState } from 'react';
import { loginWithToken } from '../../services/api';
import {
  isLocalPreviewAuthBypassEnabled,
  toLoginErrorMessage,
  validateLoginTokenInput,
  writeLocalPreviewAuthUser,
} from './loginHelpers';

export function useTokenLogin() {
  const [tokenInput, setTokenInput] = useState('');
  const [tokenLoading, setTokenLoading] = useState(false);
  const [tokenError, setTokenError] = useState('');

  const submit = async () => {
    setTokenError('');
    const parsed = validateLoginTokenInput(tokenInput);
    if (!parsed.token) {
      if (isLocalPreviewAuthBypassEnabled()) {
        writeLocalPreviewAuthUser();
        window.location.href = '/';
        return;
      }
      setTokenError(parsed.error ?? 'Token is required');
      return;
    }

    setTokenLoading(true);
    try {
      await loginWithToken(parsed.token);
      window.location.href = '/';
    } catch (err) {
      setTokenError(toLoginErrorMessage(err));
    } finally {
      setTokenLoading(false);
    }
  };

  return {
    tokenInput,
    setTokenInput,
    tokenLoading,
    tokenError,
    submit,
  };
}
