export interface AuthResponseInterface {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    emailVerified: boolean;
    isTwoFaEnabled: boolean;
    roles: string[];
    mustChangePassword?: boolean;
  };
  requiresTwoFactor?: boolean;
  redirectPath?: string;
  mustChangePassword?: boolean;
}
