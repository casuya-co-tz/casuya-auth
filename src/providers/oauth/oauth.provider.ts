import { UserProfile } from '../../interfaces';
import { AuthenticationResult, ProviderAuthRequest, ProviderLinkRequest } from '../auth-provider.interface';
import { OAuthProvider, OAuthProviderConfig, OAuthTokenResponse, OAuthProfile } from './oauth-provider.interface';

interface LinkedAccount {
  userId: string;
  providerUserId: string;
  tokenResponse: OAuthTokenResponse;
  profile: OAuthProfile;
  linkedAt: Date;
}

export abstract class OAuthBaseProvider implements OAuthProvider {
  abstract readonly config: OAuthProviderConfig;
  private readonly linkedAccounts: Map<string, LinkedAccount> = new Map();
  private readonly providerIndex: Map<string, string> = new Map();

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

  async linkAccount(request: ProviderLinkRequest): Promise<void> {
    const { userId, providerData } = request;
    const providerUserId = providerData.providerUserId as string;
    if (!providerUserId) {
      throw new Error('providerUserId is required in providerData');
    }
    const tokenResponse: OAuthTokenResponse = {
      accessToken: providerData.accessToken as string,
      refreshToken: providerData.refreshToken as string | undefined,
      expiresIn: (providerData.expiresIn as number) ?? 3600,
      tokenType: (providerData.tokenType as string) ?? 'Bearer',
      raw: (providerData.raw as Record<string, unknown>) ?? {},
    };

    let profile: OAuthProfile;
    try {
      profile = await this.getUserProfile(tokenResponse.accessToken);
    } catch {
      profile = {
        id: providerUserId,
        email: providerData.email as string ?? `${providerUserId}@oauth.local`,
        displayName: providerData.displayName as string ?? 'OAuth User',
        raw: providerData,
      };
    }

    const account: LinkedAccount = {
      userId,
      providerUserId,
      tokenResponse,
      profile,
      linkedAt: new Date(),
    };
    this.linkedAccounts.set(userId, account);
    this.providerIndex.set(providerUserId, userId);
  }

  async unlinkAccount(userId: string): Promise<void> {
    const account = this.linkedAccounts.get(userId);
    if (account) {
      this.providerIndex.delete(account.providerUserId);
      this.linkedAccounts.delete(userId);
    }
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

  getLinkedAccount(userId: string): LinkedAccount | null {
    return this.linkedAccounts.get(userId) ?? null;
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
    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.status}`);
    }
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
    this.linkedAccounts.clear();
    this.providerIndex.clear();
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await fetch(this.config.userInfoUrl, { method: 'HEAD' });
      return response.status < 500;
    } catch {
      return false;
    }
  }
}
