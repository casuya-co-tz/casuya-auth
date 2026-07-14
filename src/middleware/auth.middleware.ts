import { AuthMiddleware, AuthMiddlewareOptions, AuthenticatedRequest } from './auth.middleware.interface';
import { TokenService } from '../tokens';
import { AuthorizationService } from '../authorization';
import { PermissionAction } from '../interfaces';

export class DefaultAuthMiddleware implements AuthMiddleware {
  private readonly tokenService: TokenService;
  private readonly authorizationService: AuthorizationService;

  constructor(tokenService: TokenService, authorizationService: AuthorizationService) {
    this.tokenService = tokenService;
    this.authorizationService = authorizationService;
  }

  async authenticate(token: string): Promise<AuthenticatedRequest | null> {
    try {
      const result = await this.tokenService.verifyAccessToken(token);
      if (!result.valid || !result.payload) return null;

      const userId = result.payload.sub as string;
      const permissions = await this.authorizationService.getUserPermissions(userId);
      const roles = await this.authorizationService.getUserRoles(userId);

      return {
        userId,
        sessionId: result.payload.jti ?? '',
        tokenPayload: result.payload,
        permissions,
        roles,
      };
    } catch {
      return null;
    }
  }

  requireAuth(options?: AuthMiddlewareOptions) {
    return async (request: any, _reply: any, next?: Function) => {
      if (options?.optional && !request.headers?.authorization) {
        return next?.();
      }

      const authHeader = request.headers?.authorization as string | undefined;
      if (!authHeader) {
        throw new Error('Authorization header required');
      }

      const token = authHeader.replace('Bearer ', '');
      const authContext = await this.authenticate(token);

      if (!authContext && options?.requireAuth !== false) {
        throw new Error('Invalid or expired token');
      }

      request.auth = authContext;
      return next?.();
    };
  }

  requirePermission(resource: string, action: string) {
    return async (request: any, _reply: any, next?: Function) => {
      if (!request.auth) {
        throw new Error('Authentication required');
      }

      const result = await this.authorizationService.checkPermission({
        userId: request.auth.userId,
        resource,
        action: action as PermissionAction,
      });

      if (!result.allowed) {
        throw new Error(`Insufficient permissions: ${resource}:${action}`);
      }

      return next?.();
    };
  }

  requireRole(role: string) {
    return async (request: any, _reply: any, next?: Function) => {
      if (!request.auth) {
        throw new Error('Authentication required');
      }

      const hasRole = await this.authorizationService.hasRole(request.auth.userId, role);
      if (!hasRole) {
        throw new Error(`Required role: ${role}`);
      }

      return next?.();
    };
  }
}
