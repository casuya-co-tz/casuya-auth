import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuid } from 'uuid';
import { TokenService } from './token.service.interface';
import { TokenPayload, TokenPair, TokenVerificationResult, TokenType, TokenConfig } from '../interfaces';

interface RevokedToken {
  jti: string;
  expiresAt: Date;
}

const REVOKED_TOKENS = new Map<string, RevokedToken>();

export class JwtTokenService implements TokenService {
  private readonly config: TokenConfig;

  constructor(config: TokenConfig) {
    this.config = config;
  }

  async generateTokenPair(payload: TokenPayload): Promise<TokenPair> {
    const jti = uuid();
    const now = Math.floor(Date.now() / 1000);

    const accessPayload: TokenPayload = {
      ...payload,
      jti: `${jti}-access`,
      iat: now,
      type: TokenType.ACCESS,
    };

    const refreshPayload: TokenPayload = {
      ...payload,
      jti: `${jti}-refresh`,
      iat: now,
      type: TokenType.REFRESH,
    };

    const accessOpts: SignOptions = {
      expiresIn: this.config.accessTokenExpiration as any,
      ...(this.config.issuer ? { issuer: this.config.issuer } : {}),
      ...(this.config.audience ? { audience: this.config.audience } : {}),
    };
    const accessToken = jwt.sign(accessPayload, this.config.accessTokenSecret, accessOpts);

    const refreshOpts: SignOptions = {
      expiresIn: this.config.refreshTokenExpiration as any,
      ...(this.config.issuer ? { issuer: this.config.issuer } : {}),
      ...(this.config.audience ? { audience: this.config.audience } : {}),
    };
    const refreshToken = jwt.sign(refreshPayload, this.config.refreshTokenSecret, refreshOpts);

    const accessExp = this.parseExpiration(this.config.accessTokenExpiration);
    const refreshExp = this.parseExpiration(this.config.refreshTokenExpiration);

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: new Date(Date.now() + accessExp * 1000),
      refreshTokenExpiresAt: new Date(Date.now() + refreshExp * 1000),
    };
  }

  async verifyAccessToken(token: string): Promise<TokenVerificationResult> {
    return this.verifyTokenWithSecret(token, this.config.accessTokenSecret, TokenType.ACCESS);
  }

  async verifyRefreshToken(token: string): Promise<TokenVerificationResult> {
    return this.verifyTokenWithSecret(token, this.config.refreshTokenSecret, TokenType.REFRESH);
  }

  async generateToken(type: TokenType, payload: TokenPayload, expiresIn?: string): Promise<string> {
    const secret = type === TokenType.REFRESH ? this.config.refreshTokenSecret : this.config.accessTokenSecret;
    const exp = expiresIn ?? (type === TokenType.REFRESH ? this.config.refreshTokenExpiration : this.config.accessTokenExpiration);

    const tokenPayload: TokenPayload = {
      ...payload,
      jti: payload.jti ?? uuid(),
      iat: Math.floor(Date.now() / 1000),
      type,
    };

    const signOpts: SignOptions = {
      expiresIn: exp as any,
      ...(this.config.issuer ? { issuer: this.config.issuer } : {}),
      ...(this.config.audience ? { audience: this.config.audience } : {}),
    };
    return jwt.sign(tokenPayload, secret, signOpts);
  }

  async verifyToken(token: string, type: TokenType): Promise<TokenVerificationResult> {
    const secret = type === TokenType.REFRESH ? this.config.refreshTokenSecret : this.config.accessTokenSecret;
    return this.verifyTokenWithSecret(token, secret, type);
  }

  decodeToken(token: string): TokenPayload | null {
    try {
      return jwt.decode(token) as TokenPayload;
    } catch {
      return null;
    }
  }

  async revokeToken(jti: string, expiresAt?: Date): Promise<void> {
    REVOKED_TOKENS.set(jti, { jti, expiresAt: expiresAt ?? new Date(Date.now() + 3600 * 1000) });
  }

  async isRevoked(jti: string): Promise<boolean> {
    const entry = REVOKED_TOKENS.get(jti);
    if (!entry) return false;
    if (entry.expiresAt < new Date()) {
      REVOKED_TOKENS.delete(jti);
      return false;
    }
    return true;
  }

  async cleanup(): Promise<void> {
    const now = new Date();
    for (const [jti, entry] of REVOKED_TOKENS) {
      if (entry.expiresAt < now) {
        REVOKED_TOKENS.delete(jti);
      }
    }
  }

  private async verifyTokenWithSecret(token: string, secret: string, expectedType: TokenType): Promise<TokenVerificationResult> {
    try {
      const verifyOpts: any = {
        ...(this.config.issuer ? { issuer: this.config.issuer } : {}),
        ...(this.config.audience ? { audience: this.config.audience } : {}),
      };
      const payload = jwt.verify(token, secret, verifyOpts) as unknown as TokenPayload;

      if (payload.jti && await this.isRevoked(payload.jti)) {
        return { valid: false, error: 'Token has been revoked' };
      }

      if (payload.type && payload.type !== expectedType) {
        return { valid: false, error: 'Token type mismatch' };
      }

      return { valid: true, payload };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Token verification failed';
      return { valid: false, error: message };
    }
  }

  private parseExpiration(expiration: string): number {
    const match = expiration.match(/^(\d+)\s*(s|m|h|d)$/);
    if (!match) return 3600;
    const value = parseInt(match[1], 10);
    const unit = match[2];
    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: return 3600;
    }
  }
}
