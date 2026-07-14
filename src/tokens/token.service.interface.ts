import { TokenPayload, TokenPair, TokenVerificationResult, TokenType } from '../interfaces';

export interface TokenService {
  generateTokenPair(payload: TokenPayload): Promise<TokenPair>;
  verifyAccessToken(token: string): Promise<TokenVerificationResult>;
  verifyRefreshToken(token: string): Promise<TokenVerificationResult>;
  generateToken(type: TokenType, payload: TokenPayload, expiresIn?: string): Promise<string>;
  verifyToken(token: string, type: TokenType): Promise<TokenVerificationResult>;
  decodeToken(token: string): TokenPayload | null;
  revokeToken(jti: string): Promise<void>;
  isRevoked(jti: string): Promise<boolean>;
  cleanup(): Promise<void>;
}
