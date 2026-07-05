import bcrypt from 'bcrypt';
import { AuthProvider, AuthProviderConfig, AuthenticationResult, ProviderAuthRequest, ProviderLinkRequest } from '../auth-provider.interface';
import { UserProfile } from '../../interfaces';

export interface LocalProviderConfig extends AuthProviderConfig {
  passwordPolicy?: {
    minLength: number;
    maxLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
  };
  bcryptRounds?: number;
}

export class LocalProvider implements AuthProvider {
  readonly config: LocalProviderConfig;
  private readonly saltRounds: number;

  constructor(config: LocalProviderConfig) {
    this.config = config;
    this.saltRounds = config.bcryptRounds ?? 12;
  }

  async authenticate(request: ProviderAuthRequest): Promise<AuthenticationResult> {
    try {
      const { email, password } = request.credentials as { email?: string; password?: string };
      if (!email || !password) {
        return { success: false, error: 'Missing email or password' };
      }
      return {
        success: true,
        providerData: { email },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Local authentication failed';
      return { success: false, error: message };
    }
  }

  async validateCredentials(credentials: Record<string, unknown>): Promise<boolean> {
    const { password, passwordHash } = credentials as { password?: string; passwordHash?: string };
    if (!password || !passwordHash) return false;
    return bcrypt.compare(password, passwordHash);
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  validatePasswordAgainstPolicy(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const policy = this.config.passwordPolicy;
    if (!policy) return { valid: true, errors: [] };
    if (password.length < policy.minLength) {
      errors.push(`Password must be at least ${policy.minLength} characters`);
    }
    if (password.length > policy.maxLength) {
      errors.push(`Password must be at most ${policy.maxLength} characters`);
    }
    if (policy.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain an uppercase letter');
    }
    if (policy.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain a lowercase letter');
    }
    if (policy.requireNumbers && !/[0-9]/.test(password)) {
      errors.push('Password must contain a number');
    }
    if (policy.requireSpecialChars && !/[^A-Za-z0-9]/.test(password)) {
      errors.push('Password must contain a special character');
    }
    return { valid: errors.length === 0, errors };
  }

  async linkAccount(_request: ProviderLinkRequest): Promise<void> {
    return;
  }

  async unlinkAccount(_userId: string): Promise<void> {
    return;
  }

  async getProfile(_providerUserId: string): Promise<UserProfile | null> {
    return null;
  }

  async initialize(): Promise<void> {
    return;
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }
}
