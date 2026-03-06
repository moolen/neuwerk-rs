export type EntryField = 'key' | 'value';

export function entryFieldErrorPath(
  fieldPrefix: string,
  index: number,
  field: EntryField
): string {
  return `${fieldPrefix}.${index}.${field}`;
}

export function entryFieldError(
  errors: Record<string, string>,
  fieldPrefix: string,
  index: number,
  field: EntryField
): string | undefined {
  return errors[entryFieldErrorPath(fieldPrefix, index, field)];
}
