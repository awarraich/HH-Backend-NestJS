export type AppContext = 'staff' | 'employee';

export interface JwtPayload {
  sub: string;
  email: string;
  roles: string[];
  /**
   * The application context the token is currently scoped to. Drives which
   * shell the SPA mounts (Organization vs Employee) and which guards apply.
   * Optional for backward-compat with legacy tokens — when missing the SPA
   * falls back to inferring it from the legacy `roles[]` array.
   */
  active_role?: AppContext;
  /**
   * Roles the user CAN switch into. Lets the SPA show a role-switcher only
   * when there's another context available. Stable across the token's life
   * (changes require re-login or a fresh switch).
   */
  available_roles?: AppContext[];
  is2FAPending?: boolean;
  iat?: number;
  exp?: number;
  passwordChangedAt?: string;
}
