import { OAuthBaseProvider } from '../oauth/oauth.provider';
import { OAuthProviderConfig, OAuthTokenResponse, OAuthProfile } from '../oauth/oauth-provider.interface';
import { AuthProviderConfig } from '../auth-provider.interface';

export class GoogleProvider extends OAuthBaseProvider {
  readonly config: OAuthProviderConfig;

  constructor(config: AuthProviderConfig) {
    super();
    this.config = {
      ...config,
      clientId: (config.options?.clientId as string) ?? '',
      clientSecret: (config.options?.clientSecret as string) ?? '',
      redirectUri: (config.options?.redirectUri as string) ?? '',
      scopes: (config.options?.scopes as string[]) ?? ['openid', 'email', 'profile'],
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
    } as OAuthProviderConfig;
  }

  getAuthorizationUrl(state: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scopes.join(' '),
      state,
      access_type: 'offline',
      prompt: 'consent',
    });
    return `${this.config.authorizationUrl}?${params.toString()}`;
  }

  async exchangeCode(code: string, redirectUri: string): Promise<OAuthTokenResponse> {
    const response = await fetch(this.config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });
    const data: Record<string, unknown> = await response.json() as Record<string, unknown>;
    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string,
      expiresIn: data.expires_in as number,
      scope: data.scope as string,
      tokenType: data.token_type as string,
      idToken: data.id_token as string,
      raw: data,
    };
  }

  async getUserProfile(accessToken: string): Promise<OAuthProfile> {
    const response = await fetch(this.config.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const data: Record<string, unknown> = await response.json() as Record<string, unknown>;
    return {
      id: data.sub as string,
      email: data.email as string,
      displayName: data.name as string,
      avatarUrl: data.picture as string,
      locale: data.locale as string,
      verified: data.email_verified as boolean,
      raw: data,
    };
  }
}
