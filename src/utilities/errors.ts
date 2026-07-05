export class AuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 500,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export class AuthenticationError extends AuthError {
  constructor(message: string = 'Authentication failed', details?: Record<string, unknown>) {
    super(message, 'AUTHENTICATION_FAILED', 401, details);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends AuthError {
  constructor(message: string = 'Access denied', details?: Record<string, unknown>) {
    super(message, 'ACCESS_DENIED', 403, details);
    this.name = 'AuthorizationError';
  }
}

export class TokenExpiredError extends AuthError {
  constructor(message: string = 'Token has expired') {
    super(message, 'TOKEN_EXPIRED', 401);
    this.name = 'TokenExpiredError';
  }
}

export class TokenInvalidError extends AuthError {
  constructor(message: string = 'Token is invalid') {
    super(message, 'TOKEN_INVALID', 401);
    this.name = 'TokenInvalidError';
  }
}

export class SessionInvalidError extends AuthError {
  constructor(message: string = 'Session is invalid or expired') {
    super(message, 'SESSION_INVALID', 401);
    this.name = 'SessionInvalidError';
  }
}

export class MfaRequiredError extends AuthError {
  constructor() {
    super('Multi-factor authentication required', 'MFA_REQUIRED', 401);
    this.name = 'MfaRequiredError';
  }
}

export class AccountLockedError extends AuthError {
  constructor(message: string = 'Account has been locked') {
    super(message, 'ACCOUNT_LOCKED', 423);
    this.name = 'AccountLockedError';
  }
}

export class ProviderNotFoundError extends AuthError {
  constructor(providerId: string) {
    super(`Authentication provider ${providerId} not found`, 'PROVIDER_NOT_FOUND', 400);
    this.name = 'ProviderNotFoundError';
  }
}

export class UserNotFoundError extends AuthError {
  constructor(message: string = 'User not found') {
    super(message, 'USER_NOT_FOUND', 404);
    this.name = 'UserNotFoundError';
  }
}
