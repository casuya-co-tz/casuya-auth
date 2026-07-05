import { v4 as uuid } from 'uuid';
import { SsoService, SsoProvider, SsoLoginRequest, SsoLoginResponse, SsoCallbackRequest, SsoCallbackResponse } from './sso.service.interface';

export class DefaultSsoService implements SsoService {
  private readonly providers: Map<string, SsoProvider> = new Map();

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
    const relayState = request.relayState ?? uuid();
    return {
      redirectUrl: provider.metadataUrl ?? '',
      providerId: provider.id,
      relayState,
    };
  }

  async handleCallback(request: SsoCallbackRequest): Promise<SsoCallbackResponse> {
    const provider = this.providers.get(request.providerId);
    if (!provider) {
      return { success: false, error: `SSO provider ${request.providerId} not found` };
    }

    return {
      success: true,
      userId: uuid(),
      email: 'user@example.com',
      displayName: 'SSO User',
      providerUserId: request.token,
    };
  }

  async isEnabled(): Promise<boolean> {
    return this.providers.size > 0 && Array.from(this.providers.values()).some(p => p.enabled);
  }
}
