export interface JwtPayload {
  sub: string;
  email: string;
  roles: string[];
  is2FAPending?: boolean;
  iat?: number;
  exp?: number;
}
