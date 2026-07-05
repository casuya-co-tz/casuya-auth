export interface UserProfile {
  id: string;
  email: string;
  username: string;
  displayName: string;
  avatarUrl?: string;
  locale?: string;
  timezone?: string;
  metadata?: Record<string, unknown>;
}

export interface UserAccount {
  id: string;
  profile: UserProfile;
  emailVerified: boolean;
  phoneVerified: boolean;
  mfaEnabled: boolean;
  mfaMethod?: MfaMethod;
  roles: string[];
  permissions: string[];
  provider: string;
  providerId: string;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date;
}

export enum MfaMethod {
  TOTP = 'totp',
  SMS = 'sms',
  EMAIL = 'email',
  RECOVERY_CODE = 'recovery_code',
}

export interface CreateUserRequest {
  email: string;
  username: string;
  password: string;
  displayName: string;
  avatarUrl?: string;
  locale?: string;
  timezone?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateUserRequest {
  displayName?: string;
  avatarUrl?: string;
  locale?: string;
  timezone?: string;
  metadata?: Record<string, unknown>;
}
