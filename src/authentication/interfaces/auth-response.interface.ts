export interface AuthResponseInterface {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    emailVerified: boolean;
    isTwoFaEnabled: boolean;
    roles: string[];
  };
  requiresTwoFactor?: boolean;
  redirectPath?: string; // Suggested redirect path based on role and 2FA status
}
