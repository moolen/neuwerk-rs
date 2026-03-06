import React from 'react';
import { AuthProvider } from './components/auth/AuthProvider';
import { ThemeProvider } from './components/ThemeProvider';
import { AuthenticatedApp } from './app/AuthenticatedApp';

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AuthenticatedApp />
      </AuthProvider>
    </ThemeProvider>
  );
}
