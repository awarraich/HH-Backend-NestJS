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
    user_type?: string;
    userType?: string;
  };
  requiresTwoFactor?: boolean;
  redirectPath?: string;
  mustChangePassword?: boolean;
}
