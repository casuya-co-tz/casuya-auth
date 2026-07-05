export interface Credential {
  id: string;
  userId: string;
  provider: string;
  providerId: string;
  passwordHash?: string;
  mfaSecret?: string;
  mfaBackupCodes?: string[];
  passwordChangedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  historySize: number;
  expiryDays: number;
}

export interface CredentialStore {
  create(credential: Credential): Promise<Credential>;
  findByUserId(userId: string): Promise<Credential | null>;
  findByProvider(provider: string, providerId: string): Promise<Credential | null>;
  updatePassword(userId: string, passwordHash: string): Promise<void>;
  updateMfaSecret(userId: string, secret: string): Promise<void>;
  updateBackupCodes(userId: string, codes: string[]): Promise<void>;
  delete(userId: string): Promise<void>;
}
