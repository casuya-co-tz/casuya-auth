import bcrypt from 'bcrypt';
import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuid } from 'uuid';
import { PasswordService, PasswordValidationResult, PasswordResetRequest, PasswordChangeRequest } from './password.service.interface';

export interface PasswordServiceConfig {
  resetTokenSecret: string;
  resetTokenExpiration: string;
  bcryptRounds: number;
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  historySize: number;
}

export class DefaultPasswordService implements PasswordService {
  private readonly config: PasswordServiceConfig;
  private readonly passwordStore: Map<string, string> = new Map();

  constructor(config: Partial<PasswordServiceConfig> = {}) {
    if (!config.resetTokenSecret) {
      throw new Error('resetTokenSecret must be provided; refusing to use a default secret');
    }
    this.config = {
      resetTokenSecret: config.resetTokenSecret,
      resetTokenExpiration: config.resetTokenExpiration ?? '1h',
      bcryptRounds: config.bcryptRounds ?? 12,
      minLength: config.minLength ?? 8,
      maxLength: config.maxLength ?? 128,
      requireUppercase: config.requireUppercase ?? true,
      requireLowercase: config.requireLowercase ?? true,
      requireNumbers: config.requireNumbers ?? true,
      requireSpecialChars: config.requireSpecialChars ?? false,
      historySize: config.historySize ?? 5,
    };
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.config.bcryptRounds);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  validatePasswordStrength(password: string): PasswordValidationResult {
    const errors: string[] = [];
    let score = 0;

    if (password.length < this.config.minLength) {
      errors.push(`Password must be at least ${this.config.minLength} characters`);
    } else {
      score += Math.min(password.length / 4, 4);
    }

    if (password.length > this.config.maxLength) {
      errors.push(`Password must be at most ${this.config.maxLength} characters`);
    }

    if (this.config.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain an uppercase letter');
    } else if (/[A-Z]/.test(password)) {
      score += 1;
    }

    if (this.config.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain a lowercase letter');
    } else if (/[a-z]/.test(password)) {
      score += 1;
    }

    if (this.config.requireNumbers && !/[0-9]/.test(password)) {
      errors.push('Password must contain a number');
    } else if (/[0-9]/.test(password)) {
      score += 1;
    }

    if (this.config.requireSpecialChars && !/[^A-Za-z0-9]/.test(password)) {
      errors.push('Password must contain a special character');
    } else if (/[^A-Za-z0-9]/.test(password)) {
      score += 1;
    }

    return { valid: errors.length === 0, errors, score: Math.min(score, 10) };
  }

  async generateResetToken(userId: string): Promise<string> {
    const signOpts: SignOptions = { expiresIn: this.config.resetTokenExpiration as SignOptions['expiresIn'] };
    return jwt.sign(
      { sub: userId, jti: uuid(), type: 'password_reset' },
      this.config.resetTokenSecret,
      signOpts,
    );
  }

  async verifyResetToken(token: string): Promise<string | null> {
    try {
      const payload = jwt.verify(token, this.config.resetTokenSecret) as { sub: string; type?: string };
      if (payload.type !== 'password_reset') {
        return null;
      }
      return payload.sub;
    } catch {
      return null;
    }
  }

  async resetPassword(request: PasswordResetRequest): Promise<boolean> {
    if (request.newPassword !== request.confirmPassword) {
      return false;
    }
    const validation = this.validatePasswordStrength(request.newPassword);
    if (!validation.valid) {
      return false;
    }
    const hash = await this.hashPassword(request.newPassword);
    this.passwordStore.set(request.userId, hash);
    return true;
  }

  async changePassword(request: PasswordChangeRequest): Promise<boolean> {
    if (request.newPassword !== request.confirmPassword) {
      return false;
    }
    const validation = this.validatePasswordStrength(request.newPassword);
    if (!validation.valid) {
      return false;
    }
    const existingHash = this.passwordStore.get(request.userId);
    if (existingHash && !await this.verifyPassword(request.currentPassword, existingHash)) {
      return false;
    }
    const hash = await this.hashPassword(request.newPassword);
    this.passwordStore.set(request.userId, hash);
    return true;
  }

  async isPasswordCompromised(password: string): Promise<boolean> {
    const commonPasswords = [
      'password', '123456', '12345678', 'qwerty', 'abc123',
      'monkey', 'master', 'dragon', 'login', 'princess',
      'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou',
    ];
    return commonPasswords.includes(password.toLowerCase());
  }
}
