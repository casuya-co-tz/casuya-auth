import { AuthProvider, AuthProviderConfig } from '../auth-provider.interface';

export interface OAuthProviderConfig extends AuthProviderConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
}

export interface OAuthTokenResponse {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  scope?: string;
  tokenType: string;
  idToken?: string;
  raw: Record<string, unknown>;
}

export interface OAuthProfile {
  id: string;
  email: string;
  displayName: string;
  avatarUrl?: string;
  locale?: string;
  verified?: boolean;
  raw: Record<string, unknown>;
}

export interface OAuthProvider extends AuthProvider {
  readonly config: OAuthProviderConfig;
  getAuthorizationUrl(state: string): string;
  exchangeCode(code: string, redirectUri: string): Promise<OAuthTokenResponse>;
  refreshAccessToken(refreshToken: string): Promise<OAuthTokenResponse>;
  getUserProfile(accessToken: string): Promise<OAuthProfile>;
}
