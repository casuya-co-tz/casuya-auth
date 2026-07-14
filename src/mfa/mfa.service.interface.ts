import { MfaMethod } from '../interfaces';

export interface MfaSetupResult {
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
  method: MfaMethod;
}

export interface MfaVerificationResult {
  verified: boolean;
  error?: string;
}

export interface SendVerificationCodeResult {
  sent: boolean;
  expiresIn: number;
}

export interface MfaService {
  setupMfa(userId: string, method: MfaMethod): Promise<MfaSetupResult>;
  verifyMfa(userId: string, code: string, method: MfaMethod): Promise<MfaVerificationResult>;
  disableMfa(userId: string): Promise<void>;
  generateBackupCodes(userId: string): Promise<string[]>;
  verifyBackupCode(userId: string, code: string): Promise<boolean>;
  isMfaEnabled(userId: string): Promise<boolean>;
  getEnabledMethods(userId: string): Promise<MfaMethod[]>;
  sendVerificationCode(userId: string, method: MfaMethod.SMS | MfaMethod.EMAIL, contactInfo: string): Promise<SendVerificationCodeResult>;
}
