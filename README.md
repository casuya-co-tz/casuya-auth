# ═══════════════════════════════════════════
# CASUYA AUTH · Security Office
# ═══════════════════════════════════════════

**Repository:** `casuya-auth`
**Phase:** 3 — Platform Services Architecture
**Identity:** Identity and Access Management System

---

## TABLE OF CONTENTS

1. [Mission](#mission)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Modules](#modules)
5. [Provider System](#provider-system)
6. [API Reference](#api-reference)
7. [Testing](#testing)
8. [Extending](#extending)
9. [Design Rules](#design-rules)

---

## MISSION

Provide authentication and authorization for the entire Casuya ecosystem.
Think of this as the **Security Office** — every user, every session, every permission flows through here.

**Problems Solved:**
- Identity verification
- Permissions and access control
- Session security
- Single Sign-On (SSO)
- Multi-factor authentication
- Audit logging

---

## ARCHITECTURE

```
casuya-auth/
│
├── src/
│   ├── authentication/     Login, register, session refresh
│   ├── authorization/       Permission checking, RBAC
│   ├── sessions/            Session lifecycle management
│   ├── tokens/              JWT access & refresh tokens
│   ├── passwords/           Hashing, strength, reset
│   ├── policies/            Rule-based access policies
│   ├── permissions/         Permission CRUD & assignment
│   ├── providers/           Auth provider abstraction layer
│   │   ├── local/           Email/password authentication
│   │   ├── google/          Google OAuth 2.0
│   │   ├── microsoft/       Microsoft OAuth 2.0
│   │   └── oauth/           Generic OAuth base provider
│   ├── mfa/                 TOTP multi-factor authentication
│   ├── sso/                 Single Sign-On (OIDC, SAML, LDAP)
│   ├── audit/               Security event logging
│   ├── middleware/           Express-compatible auth guards
│   ├── interfaces/          Shared TypeScript interfaces
│   └── utilities/           Crypto, validators, errors
│
├── tests/                   Jest test suites
├── package.json
└── tsconfig.json
```

---

## QUICK START

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run all tests
npm test

# Type-check without emitting
npm run typecheck
```

### Basic Usage

```typescript
import {
  DefaultAuthenticationService,
  JwtTokenService,
  DefaultSessionService,
  LocalProvider,
} from '@casuya/auth';

// 1. Create token service
const tokenService = new JwtTokenService({
  accessTokenSecret: process.env.JWT_ACCESS_SECRET!,
  refreshTokenSecret: process.env.JWT_REFRESH_SECRET!,
  accessTokenExpiration: '15m',
  refreshTokenExpiration: '7d',
});

// 2. Create storage (implement SessionStore, etc.)
const sessionStore = new YourSessionStore();
const userStore = new YourUserStore();

// 3. Create auth service
const authService = new DefaultAuthenticationService(
  tokenService,
  sessionStore,
  userStore,
);

// 4. Register providers
authService.registerProvider(new LocalProvider({
  id: 'local',
  name: 'Email & Password',
  type: 'local',
  enabled: true,
  passwordPolicy: {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
  },
}));

// 5. Authenticate
const result = await authService.login({
  provider: 'local',
  credentials: { email: 'user@school.edu', password: '...' },
});
```

---

## MODULES

### Authentication

Handles login, registration, logout, and session refresh.

| Method | Description |
|--------|-------------|
| `login(request)` | Authenticate via any registered provider |
| `register(request)` | Create new user account |
| `logout(sessionId, userId)` | Invalidate session |
| `logoutAllSessions(userId)` | Invalidate all user sessions |
| `refreshSession(refreshToken)` | Exchange refresh token for new token pair |
| `verifyEmail(token)` | Verify email address |

### Authorization

Role-Based Access Control (RBAC) with permission checking.

| Method | Description |
|--------|-------------|
| `checkPermission(check)` | Check if user can perform action on resource |
| `checkPermissions(checks)` | Batch permission check |
| `hasRole(userId, roleName)` | Check if user has role |
| `assignRole(userId, roleName)` | Assign role to user |
| `revokeRole(userId, roleName)` | Remove role from user |

### Sessions

Session lifecycle management.

| Method | Description |
|--------|-------------|
| `createSession(request)` | Create new session |
| `getSession(sessionId)` | Get session by ID |
| `getUserSessions(userId)` | Get all sessions for user |
| `invalidateSession(sessionId)` | Invalidate single session |
| `cleanupExpiredSessions()` | Remove expired sessions |

### Tokens

JWT-based token management.

| Method | Description |
|--------|-------------|
| `generateTokenPair(payload)` | Create access + refresh token pair |
| `verifyAccessToken(token)` | Validate access token |
| `verifyRefreshToken(token)` | Validate refresh token |
| `revokeToken(jti)` | Revoke token by JWT ID |
| `generateToken(type, payload)` | Create one-time tokens (email verification, password reset, MFA) |

### Passwords

Password security.

| Method | Description |
|--------|-------------|
| `hashPassword(password)` | BCrypt hash |
| `verifyPassword(password, hash)` | Compare password against hash |
| `validatePasswordStrength(password)` | Check against configurable policy |
| `generateResetToken(userId)` | Create password reset token |
| `verifyResetToken(token)` | Validate reset token |

### Policies

Rule-based access policies with conditional evaluation.

| Method | Description |
|--------|-------------|
| `createPolicy(policy)` | Create access policy with rules |
| `evaluate(request)` | Evaluate access against all policies |
| `evaluateBatch(requests)` | Batch evaluation |
| `getAllPolicies()` | List all policies sorted by priority |

### MFA

Multi-factor authentication (TOTP).

| Method | Description |
|--------|-------------|
| `setupMfa(userId, method)` | Generate TOTP secret, QR code, backup codes |
| `verifyMfa(userId, code, method)` | Verify TOTP code |
| `verifyBackupCode(userId, code)` | Verify and consume backup code |
| `disableMfa(userId)` | Remove MFA configuration |

### SSO

Single Sign-On provider management.

| Method | Description |
|--------|-------------|
| `registerProvider(provider)` | Register SSO provider (OIDC, SAML, LDAP) |
| `initiateLogin(request)` | Generate SSO redirect URL |
| `handleCallback(request)` | Process SSO callback |
| `getProviders()` | List enabled SSO providers |

### Audit

Security event logging.

| Method | Description |
|--------|-------------|
| `record(event)` | Log security event |
| `query(query)` | Query audit log with filters |
| `getByUser(userId)` | Get events for specific user |
| `getFailedEvents()` | Get failed authentication attempts |
| `export()` | Export audit log |

---

## PROVIDER SYSTEM

The provider system is the core extension mechanism (Phase 3 Rule 4).

### AuthProvider Interface

```typescript
interface AuthProvider {
  readonly config: AuthProviderConfig;
  authenticate(request: ProviderAuthRequest): Promise<AuthenticationResult>;
  validateCredentials(credentials): Promise<boolean>;
  linkAccount(request: ProviderLinkRequest): Promise<void>;
  unlinkAccount(userId: string): Promise<void>;
  getProfile(providerUserId: string): Promise<UserProfile | null>;
  initialize(): Promise<void>;
  healthCheck(): Promise<boolean>;
}
```

### Built-in Providers

| Provider | Type | Description |
|----------|------|-------------|
| `LocalProvider` | local | Email/password with BCrypt |
| `GoogleProvider` | oauth | Google Sign-In (OAuth 2.0) |
| `MicrosoftProvider` | oauth | Microsoft/Entra ID (OAuth 2.0) |

### Adding a New Provider

```typescript
import { AuthProvider, AuthProviderConfig, AuthenticationResult } from '@casuya/auth';

class GitHubProvider implements AuthProvider {
  config: AuthProviderConfig = {
    id: 'github',
    name: 'GitHub',
    type: 'oauth',
    enabled: true,
  };

  async authenticate(request: ProviderAuthRequest): Promise<AuthenticationResult> {
    // Implement GitHub OAuth flow
  }
  // ... implement remaining methods
}

authService.registerProvider(new GitHubProvider());
```

---

## TESTING

```bash
# Run all tests
npm test

# Run with watch mode
npm run test:watch

# View coverage
# Open coverage/lcov-report/index.html in browser
```

**Test suites:** 10 suites, 49 tests covering all modules.

---

## EXTENDING

### Adding a New Provider

1. Create `src/providers/<name>/<name>.provider.ts`
2. Implement `AuthProvider` interface
3. Export from `src/providers/index.ts`
4. Register via `authService.registerProvider()`

### Adding a New Permission

```typescript
await permissionService.grantPermission('user-1', 'lessons:create');
```

### Adding a New Policy

```typescript
await policyService.createPolicy({
  name: 'Restrict Exam Access',
  rules: [{
    id: 'rule-exam',
    name: 'exam-access',
    effect: 'deny',
    resources: ['exam:*'],
    actions: [PermissionAction.READ],
    conditions: [{ field: 'role', operator: 'neq', value: 'teacher' }],
    priority: 1,
  }],
  isEnabled: true,
  priority: 1,
});
```

---

## DESIGN RULES

This repository follows the **Phase 3 Platform Services Architecture Constitution:**

| # | Rule | How We Follow It |
|---|------|------------------|
| 1 | Build generic services | No school-specific logic; generic IAM |
| 2 | Everything extensible | Provider system, plugin-ready interfaces |
| 3 | No internal knowledge | API-first; stores are injectable interfaces |
| 4 | Provider-based | `providers/` directory with pluggable auth providers |
| 5 | Everything replaceable | Swap any provider without breaking the platform |
| 6 | Stay lightweight | No business logic, no school code |
| 7 | Assume large scale | Stateless JWT, paginated queries, async everywhere |
| 8 | API-first | Every module exports its interface before implementation |

---

## LICENSE

MIT — Casuya Platform Services
