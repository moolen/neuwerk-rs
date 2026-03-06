export function validateTlsInterceptCaInput(certPem: string, keyPem: string): string | null {
  if (!certPem.trim() || !keyPem.trim()) {
    return 'Certificate PEM and key PEM are required';
  }
  return null;
}
