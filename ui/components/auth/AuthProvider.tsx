import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import type { AuthUser } from '../../types';
import { getAuthToken, clearAuthToken, whoAmI, logout as apiLogout } from '../../services/api';

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  error: string | null;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    checkAuth();
  }, []);

  async function checkAuth() {
    const token = getAuthToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }

    try {
      const data = await whoAmI();
      setUser(data);
    } catch (err) {
      clearAuthToken();
      setUser(null);
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to check authentication');
      }
    } finally {
      setLoading(false);
    }
  }

  async function logout() {
    try {
      await apiLogout();
    } catch {
      // ignore
    } finally {
      setUser(null);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ background: 'var(--bg)' }}>
        <div className="text-lg" style={{ color: 'var(--text-muted)' }}>Loading...</div>
      </div>
    );
  }

  return (
    <AuthContext.Provider value={{ user, loading, error, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
