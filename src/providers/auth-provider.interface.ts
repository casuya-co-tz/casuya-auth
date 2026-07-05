import { UserProfile } from '../interfaces';

export interface AuthProviderConfig {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  options?: Record<string, unknown>;
}

export interface AuthenticationResult {
  success: boolean;
  userId?: string;
  profile?: UserProfile;
  error?: string;
  providerData?: Record<string, unknown>;
}

export interface ProviderAuthRequest {
  credentials: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

export interface ProviderLinkRequest {
  userId: string;
  providerId: string;
  providerData: Record<string, unknown>;
}

export interface AuthProvider {
  readonly config: AuthProviderConfig;
  authenticate(request: ProviderAuthRequest): Promise<AuthenticationResult>;
  validateCredentials(credentials: Record<string, unknown>): Promise<boolean>;
  linkAccount(request: ProviderLinkRequest): Promise<void>;
  unlinkAccount(userId: string): Promise<void>;
  getProfile(providerUserId: string): Promise<UserProfile | null>;
  initialize(): Promise<void>;
  healthCheck(): Promise<boolean>;
}
