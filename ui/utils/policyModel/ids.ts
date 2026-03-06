export function nextNamedId(prefix: string, existingIds: string[]): string {
  const seen = new Set(existingIds.map((id) => id.trim()).filter(Boolean));
  let i = 1;
  while (seen.has(`${prefix}-${i}`)) i += 1;
  return `${prefix}-${i}`;
}
