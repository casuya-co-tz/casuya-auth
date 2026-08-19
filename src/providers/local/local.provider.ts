import { v4 as uuid } from 'uuid';
import bcrypt from 'bcrypt';
import { AuthProvider, AuthProviderConfig, AuthenticationResult, ProviderAuthRequest, ProviderLinkRequest } from '../auth-provider.interface';
import { UserProfile } from '../../interfaces';
import type { BcryptWorkerPool } from '../../workers/bcrypt-pool';

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
  bcryptPool?: BcryptWorkerPool;
}

interface StoredAccount {
  userId: string;
  email: string;
  passwordHash: string;
  profile: UserProfile;
  linkedProviders: Map<string, Record<string, unknown>>;
}

export class LocalProvider implements AuthProvider {
  readonly config: LocalProviderConfig;
  private readonly saltRounds: number;
  private readonly accounts: Map<string, StoredAccount> = new Map();
  private readonly emailIndex: Map<string, string> = new Map();
  private readonly bcryptPool: BcryptWorkerPool | null;

  constructor(config: LocalProviderConfig) {
    this.config = config;
    this.saltRounds = config.bcryptRounds ?? 12;
    this.bcryptPool = config.bcryptPool ?? null;
  }

  async authenticate(request: ProviderAuthRequest): Promise<AuthenticationResult> {
    try {
      const { email, password, passwordHash } = request.credentials as { email?: string; password?: string; passwordHash?: string };
      if (!email || !password) {
        return { success: false, error: 'Missing email or password' };
      }

      if (passwordHash) {
        const valid = await this.validateCredentials({ password, passwordHash });
        if (!valid) {
          return { success: false, error: 'Invalid email or password' };
        }
        return { success: true, providerData: { email } };
      }

      const userId = this.emailIndex.get(email.toLowerCase());
      if (!userId) {
        return { success: false, error: 'Invalid email or password' };
      }
      const account = this.accounts.get(userId)!;
      const valid = await this.validateCredentials({ password, passwordHash: account.passwordHash });
      if (!valid) {
        return { success: false, error: 'Invalid email or password' };
      }

      return {
        success: true,
        userId: account.userId,
        profile: account.profile,
        providerData: { email: account.email },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Local authentication failed';
      return { success: false, error: message };
    }
  }

  async validateCredentials(credentials: Record<string, unknown>): Promise<boolean> {
    const { password, passwordHash } = credentials as { password?: string; passwordHash?: string };
    if (!password || !passwordHash) return false;
    if (this.bcryptPool) {
      return this.bcryptPool.compare(password, passwordHash);
    }
    return bcrypt.compare(password, passwordHash);
  }

  async hashPassword(password: string): Promise<string> {
    if (this.bcryptPool) {
      return this.bcryptPool.hash(password);
    }
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

  async createUser(email: string, password: string, displayName: string): Promise<UserProfile> {
    const normalizedEmail = email.toLowerCase();
    if (this.emailIndex.has(normalizedEmail)) {
      throw new Error('A user with this email already exists');
    }
    const policyResult = this.validatePasswordAgainstPolicy(password);
    if (!policyResult.valid) {
      throw new Error(`Password policy violation: ${policyResult.errors.join('; ')}`);
    }

    const userId = uuid();
    const passwordHash = await this.hashPassword(password);
    const profile: UserProfile = {
      id: userId,
      email: normalizedEmail,
      username: normalizedEmail.split('@')[0],
      displayName,
    };
    const account: StoredAccount = {
      userId,
      email: normalizedEmail,
      passwordHash,
      profile,
      linkedProviders: new Map(),
    };
    this.accounts.set(userId, account);
    this.emailIndex.set(normalizedEmail, userId);
    return profile;
  }

  async deleteUser(userId: string): Promise<boolean> {
    const account = this.accounts.get(userId);
    if (!account) return false;
    this.emailIndex.delete(account.email);
    this.accounts.delete(userId);
    return true;
  }

  async getUserById(userId: string): Promise<UserProfile | null> {
    return this.accounts.get(userId)?.profile ?? null;
  }

  async updatePassword(userId: string, newPassword: string): Promise<boolean> {
    const account = this.accounts.get(userId);
    if (!account) return false;
    const policyResult = this.validatePasswordAgainstPolicy(newPassword);
    if (!policyResult.valid) {
      throw new Error(`Password policy violation: ${policyResult.errors.join('; ')}`);
    }
    account.passwordHash = await this.hashPassword(newPassword);
    return true;
  }

  async linkAccount(request: ProviderLinkRequest): Promise<void> {
    const account = this.accounts.get(request.userId);
    if (!account) {
      throw new Error(`User ${request.userId} not found`);
    }
    account.linkedProviders.set(request.providerId, request.providerData);
  }

  async unlinkAccount(userId: string): Promise<void> {
    const account = this.accounts.get(userId);
    if (!account) {
      throw new Error(`User ${userId} not found`);
    }
    account.linkedProviders.clear();
  }

  async getProfile(providerUserId: string): Promise<UserProfile | null> {
    return this.accounts.get(providerUserId)?.profile ?? null;
  }

  async initialize(): Promise<void> {
    this.accounts.clear();
    this.emailIndex.clear();
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.hashPassword('health-check-test');
      return true;
    } catch {
      return false;
    }
  }
}
