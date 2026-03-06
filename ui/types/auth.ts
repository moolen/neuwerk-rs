export interface AuthUser {
  sub: string;
  sa_id?: string | null;
  exp?: number | null;
  roles: string[];
}
