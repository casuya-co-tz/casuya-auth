import { v4 as uuid } from 'uuid';
import { SsoService, SsoProvider, SsoLoginRequest, SsoLoginResponse, SsoCallbackRequest, SsoCallbackResponse, SsoProtocol } from './sso.service.interface';

interface SsoSession {
  relayState: string;
  providerId: string;
  initiatedAt: Date;
  attributes?: Record<string, string>;
}

export class DefaultSsoService implements SsoService {
  private readonly providers: Map<string, SsoProvider> = new Map();
  private readonly sessions: Map<string, SsoSession> = new Map();
  private readonly userMappings: Map<string, { userId: string; email: string; displayName: string }> = new Map();

  async getProviders(): Promise<SsoProvider[]> {
    return Array.from(this.providers.values()).filter(p => p.enabled);
  }

  async getProvider(providerId: string): Promise<SsoProvider | null> {
    return this.providers.get(providerId) ?? null;
  }

  async registerProvider(provider: SsoProvider): Promise<void> {
    this.providers.set(provider.id, provider);
  }

  async unregisterProvider(providerId: string): Promise<void> {
    this.providers.delete(providerId);
  }

  async initiateLogin(request: SsoLoginRequest): Promise<SsoLoginResponse> {
    const provider = this.providers.get(request.providerId);
    if (!provider) {
      throw new Error(`SSO provider ${request.providerId} not found`);
    }
    if (!provider.enabled) {
      throw new Error(`SSO provider ${request.providerId} is disabled`);
    }

    const relayState = request.relayState ?? uuid();
    this.sessions.set(relayState, {
      relayState,
      providerId: provider.id,
      initiatedAt: new Date(),
      attributes: request.attributes,
    });

    const redirectUrl = this.buildRedirectUrl(provider, relayState);
    return {
      redirectUrl,
      providerId: provider.id,
      relayState,
    };
  }

  async handleCallback(request: SsoCallbackRequest): Promise<SsoCallbackResponse> {
    const provider = this.providers.get(request.providerId);
    if (!provider) {
      return { success: false, error: `SSO provider ${request.providerId} not found` };
    }

    if (!provider.enabled) {
      return { success: false, error: `SSO provider ${request.providerId} is disabled` };
    }

    const session = request.relayState ? this.sessions.get(request.relayState) : undefined;
    if (request.relayState && session) {
      this.sessions.delete(request.relayState);
    }

    try {
      const claims = await this.verifyAndExtractClaims(provider, request.token);

      const existingMapping = this.userMappings.get(`${provider.id}:${claims.sub}`);
      const userId = existingMapping?.userId ?? uuid();
      const email = claims.email ?? `${claims.sub}@${provider.id}.sso`;
      const displayName = claims.name ?? claims.preferred_username ?? email.split('@')[0];

      if (!existingMapping) {
        this.userMappings.set(`${provider.id}:${claims.sub}`, { userId, email, displayName });
      }

      return {
        success: true,
        userId,
        email,
        displayName,
        providerUserId: claims.sub,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'SSO callback verification failed';
      return { success: false, error: message };
    }
  }

  async isEnabled(): Promise<boolean> {
    return this.providers.size > 0 && Array.from(this.providers.values()).some(p => p.enabled);
  }

  async mapUser(providerId: string, providerUserId: string, userId: string, email: string, displayName: string): Promise<void> {
    this.userMappings.set(`${providerId}:${providerUserId}`, { userId, email, displayName });
  }

  async getMappedUser(providerId: string, providerUserId: string): Promise<{ userId: string; email: string; displayName: string } | null> {
    return this.userMappings.get(`${providerId}:${providerUserId}`) ?? null;
  }

  private buildRedirectUrl(provider: SsoProvider, relayState: string): string {
    const base = provider.metadataUrl ?? '';
    switch (provider.type) {
      case SsoProtocol.SAML: {
        const params = new URLSearchParams({
          SAMLRequest: Buffer.from(JSON.stringify({ providerId: provider.id, relayState })).toString('base64'),
          RelayState: relayState,
        });
        return `${base}?${params.toString()}`;
      }
      case SsoProtocol.OIDC: {
        const params = new URLSearchParams({
          response_type: 'code',
          client_id: provider.entityId ?? provider.id,
          redirect_uri: base,
          scope: 'openid email profile',
          state: relayState,
        });
        return `${base}?${params.toString()}`;
      }
      case SsoProtocol.LDAP:
        return base;
      default:
        return base;
    }
  }

  private async verifyAndExtractClaims(provider: SsoProvider, token: string): Promise<Record<string, string>> {
    switch (provider.type) {
      case SsoProtocol.SAML:
        return this.parseSamlToken(token);
      case SsoProtocol.OIDC:
        return this.parseOidcToken(token);
      case SsoProtocol.LDAP:
        return this.parseLdapToken(token);
      default:
        throw new Error(`Unsupported SSO protocol: ${provider.type}`);
    }
  }

  private parseSamlToken(token: string): Record<string, string> {
    try {
      const decoded = Buffer.from(token, 'base64').toString('utf-8');
      const claims = JSON.parse(decoded);
      if (!claims.sub) {
        throw new Error('SAML token missing subject');
      }
      return claims;
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('Invalid SAML token format');
      }
      throw error;
    }
  }

  private parseOidcToken(token: string): Record<string, string> {
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));
        if (!payload.sub) {
          throw new Error('OIDC token missing subject');
        }
        return payload;
      }
      const decoded = Buffer.from(token, 'base64').toString('utf-8');
      return JSON.parse(decoded);
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('Invalid OIDC token format');
      }
      throw error;
    }
  }

  private parseLdapToken(token: string): Record<string, string> {
    try {
      const decoded = Buffer.from(token, 'base64').toString('utf-8');
      const claims = JSON.parse(decoded);
      if (!claims.sub && !claims.cn) {
        throw new Error('LDAP token missing subject or common name');
      }
      return { sub: claims.sub ?? claims.cn, ...claims };
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('Invalid LDAP token format');
      }
      throw error;
    }
  }
}
