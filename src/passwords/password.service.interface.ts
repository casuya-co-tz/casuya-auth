export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
  score: number;
}

export interface PasswordResetRequest {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

export interface PasswordChangeRequest {
  userId: string;
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface PasswordService {
  hashPassword(password: string): Promise<string>;
  verifyPassword(password: string, hash: string): Promise<boolean>;
  validatePasswordStrength(password: string): PasswordValidationResult;
  generateResetToken(userId: string): Promise<string>;
  verifyResetToken(token: string): Promise<string | null>;
  resetPassword(request: PasswordResetRequest): Promise<boolean>;
  changePassword(request: PasswordChangeRequest): Promise<boolean>;
  isPasswordCompromised(password: string): Promise<boolean>;
}
