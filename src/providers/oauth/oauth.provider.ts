import { UserProfile } from '../../interfaces';
import { AuthenticationResult, ProviderAuthRequest, ProviderLinkRequest } from '../auth-provider.interface';
import { OAuthProvider, OAuthProviderConfig, OAuthTokenResponse, OAuthProfile } from './oauth-provider.interface';

export abstract class OAuthBaseProvider implements OAuthProvider {
  abstract readonly config: OAuthProviderConfig;

  abstract getAuthorizationUrl(state: string): string;

  abstract exchangeCode(code: string, redirectUri: string): Promise<OAuthTokenResponse>;

  abstract getUserProfile(accessToken: string): Promise<OAuthProfile>;

  async authenticate(request: ProviderAuthRequest): Promise<AuthenticationResult> {
    try {
      const { code, redirectUri } = request.credentials as { code?: string; redirectUri?: string };
      if (!code || !redirectUri) {
        return { success: false, error: 'Missing authorization code or redirect URI' };
      }
      const tokenResponse = await this.exchangeCode(code, redirectUri);
      const profile = await this.getUserProfile(tokenResponse.accessToken);
      return {
        success: true,
        userId: profile.id,
        profile: {
          id: profile.id,
          email: profile.email,
          username: profile.email.split('@')[0],
          displayName: profile.displayName,
          avatarUrl: profile.avatarUrl,
          locale: profile.locale,
        },
        providerData: {
          accessToken: tokenResponse.accessToken,
          refreshToken: tokenResponse.refreshToken,
          expiresIn: tokenResponse.expiresIn,
          raw: tokenResponse.raw,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'OAuth authentication failed';
      return { success: false, error: message };
    }
  }

  async validateCredentials(credentials: Record<string, unknown>): Promise<boolean> {
    try {
      const { accessToken } = credentials as { accessToken?: string };
      if (!accessToken) return false;
      await this.getUserProfile(accessToken);
      return true;
    } catch {
      return false;
    }
  }

  async linkAccount(_request: ProviderLinkRequest): Promise<void> {
    return;
  }

  async unlinkAccount(_userId: string): Promise<void> {
    return;
  }

  async getProfile(providerUserId: string): Promise<UserProfile | null> {
    try {
      const profile = await this.getUserProfile(providerUserId);
      return {
        id: profile.id,
        email: profile.email,
        username: profile.email.split('@')[0],
        displayName: profile.displayName,
        avatarUrl: profile.avatarUrl,
        locale: profile.locale,
      };
    } catch {
      return null;
    }
  }

  async refreshAccessToken(refreshToken: string): Promise<OAuthTokenResponse> {
    const response = await fetch(this.config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      }),
    });
    const data: any = await response.json();
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresIn: data.expires_in,
      scope: data.scope,
      tokenType: data.token_type,
      raw: data as Record<string, unknown>,
    };
  }

  async initialize(): Promise<void> {
    return;
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }
}
