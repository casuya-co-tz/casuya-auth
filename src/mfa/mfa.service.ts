import { v4 as uuid } from 'uuid';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { MfaService, MfaSetupResult, MfaVerificationResult } from './mfa.service.interface';
import { MfaMethod } from '../interfaces';

interface MfaState {
  userId: string;
  method: MfaMethod;
  secret: string;
  enabled: boolean;
  backupCodes: string[];
  usedBackupCodes: string[];
}

export class DefaultMfaService implements MfaService {
  private readonly mfaStates: Map<string, MfaState> = new Map();
  private readonly issuer: string;

  constructor(issuer: string = 'Casuya') {
    this.issuer = issuer;
  }

  async setupMfa(userId: string, method: MfaMethod): Promise<MfaSetupResult> {
    const secret = speakeasy.generateSecret({
      name: `${this.issuer}:${userId}`,
      issuer: this.issuer,
    });

    const backupCodes = Array.from({ length: 10 }, () => uuid().replace(/-/g, '').substring(0, 10));

    let qrCodeUrl = '';
    if (method === MfaMethod.TOTP && secret.otpauth_url) {
      qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    }

    const state: MfaState = {
      userId,
      method,
      secret: secret.base32 ?? '',
      enabled: false,
      backupCodes,
      usedBackupCodes: [],
    };
    this.mfaStates.set(userId, state);

    return {
      secret: state.secret,
      qrCodeUrl,
      backupCodes,
      method,
    };
  }

  async verifyMfa(userId: string, code: string, method: MfaMethod): Promise<MfaVerificationResult> {
    const state = this.mfaStates.get(userId);
    if (!state) {
      return { verified: false, error: 'MFA not set up' };
    }

    if (method === MfaMethod.TOTP) {
      const verified = speakeasy.totp.verify({
        secret: state.secret,
        encoding: 'base32',
        token: code,
        window: 1,
      });

      if (verified) {
        state.enabled = true;
      }

      return { verified, error: verified ? undefined : 'Invalid code' };
    }

    return { verified: false, error: `MFA method ${method} not implemented` };
  }

  async disableMfa(userId: string): Promise<void> {
    this.mfaStates.delete(userId);
  }

  async generateBackupCodes(userId: string): Promise<string[]> {
    const state = this.mfaStates.get(userId);
    if (!state) throw new Error('MFA not set up');
    const newCodes = Array.from({ length: 10 }, () => uuid().replace(/-/g, '').substring(0, 10));
    state.backupCodes = newCodes;
    state.usedBackupCodes = [];
    return newCodes;
  }

  async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const state = this.mfaStates.get(userId);
    if (!state) return false;

    const index = state.backupCodes.indexOf(code);
    if (index === -1 || state.usedBackupCodes.includes(code)) return false;

    state.usedBackupCodes.push(code);
    state.backupCodes.splice(index, 1);
    return true;
  }

  async isMfaEnabled(userId: string): Promise<boolean> {
    return this.mfaStates.get(userId)?.enabled ?? false;
  }

  async getEnabledMethods(userId: string): Promise<MfaMethod[]> {
    const state = this.mfaStates.get(userId);
    if (!state || !state.enabled) return [];
    return [state.method];
  }
}
