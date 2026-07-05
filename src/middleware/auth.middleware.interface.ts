export interface AuthenticatedRequest {
  userId: string;
  sessionId: string;
  tokenPayload: Record<string, unknown>;
  permissions: string[];
  roles: string[];
  ipAddress?: string;
  userAgent?: string;
}

export interface AuthMiddlewareOptions {
  requireAuth: boolean;
  requiredPermissions?: string[];
  requiredRoles?: string[];
  optional?: boolean;
}

export interface AuthMiddleware {
  authenticate(token: string): Promise<AuthenticatedRequest | null>;
  requireAuth(options?: AuthMiddlewareOptions): any;
  requirePermission(resource: string, action: string): any;
  requireRole(role: string): any;
}
