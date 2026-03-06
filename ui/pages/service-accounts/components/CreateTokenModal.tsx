import React, { useState } from 'react';
import type { CreateServiceAccountTokenRequest } from '../../../types';
import { CreateTokenModalActions } from './CreateTokenModalActions';
import { CreateTokenModalFields } from './CreateTokenModalFields';
import { buildCreateTokenRequest } from './createTokenForm';

interface CreateTokenModalProps {
  onClose: () => void;
  onSubmit: (req: CreateServiceAccountTokenRequest) => void;
}

export const CreateTokenModal: React.FC<CreateTokenModalProps> = ({ onClose, onSubmit }) => {
  const [name, setName] = useState('');
  const [ttl, setTtl] = useState('');
  const [eternal, setEternal] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(buildCreateTokenRequest(name, ttl, eternal));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50" onClick={onClose} />
      <div
        className="relative rounded-xl border p-6 max-w-md w-full shadow-xl my-auto"
        style={{ background: 'var(--bg-glass-strong)', borderColor: 'var(--border-glass)' }}
      >
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text)' }}>
          Create Token
        </h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <CreateTokenModalFields
            name={name}
            ttl={ttl}
            eternal={eternal}
            onNameChange={setName}
            onTtlChange={setTtl}
            onEternalChange={setEternal}
          />
          <CreateTokenModalActions onClose={onClose} />
        </form>
      </div>
    </div>
  );
};
