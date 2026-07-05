export interface SsoProvider {
  id: string;
  name: string;
  type: SsoProtocol;
  enabled: boolean;
  metadataUrl?: string;
  entityId?: string;
  certificate?: string;
}

export enum SsoProtocol {
  SAML = 'saml',
  OIDC = 'oidc',
  LDAP = 'ldap',
}

export interface SsoLoginRequest {
  providerId: string;
  relayState?: string;
  attributes?: Record<string, string>;
}

export interface SsoLoginResponse {
  redirectUrl: string;
  providerId: string;
  relayState: string;
}

export interface SsoCallbackRequest {
  providerId: string;
  token: string;
  relayState?: string;
}

export interface SsoCallbackResponse {
  success: boolean;
  userId?: string;
  email?: string;
  displayName?: string;
  providerUserId?: string;
  error?: string;
}

export interface SsoService {
  getProviders(): Promise<SsoProvider[]>;
  getProvider(providerId: string): Promise<SsoProvider | null>;
  registerProvider(provider: SsoProvider): Promise<void>;
  unregisterProvider(providerId: string): Promise<void>;
  initiateLogin(request: SsoLoginRequest): Promise<SsoLoginResponse>;
  handleCallback(request: SsoCallbackRequest): Promise<SsoCallbackResponse>;
  isEnabled(): Promise<boolean>;
}
