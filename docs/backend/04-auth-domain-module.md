# Auth Domain Module

## Module Purpose

Implement secure authentication workflows including registration, login, logout, and token refresh. This module orchestrates the authentication process while delegating token management and user operations to their respective modules.

---

## Responsibilities

### MUST Do:
- Orchestrate user registration workflow
- Validate credentials during login
- Issue access and refresh tokens
- Handle logout and session invalidation
- Implement password reset flow
- Emit authentication events for audit logging

### MUST NOT Do:
- Store or manage tokens directly (delegated to Token module)
- Handle user CRUD operations (delegated to User module)
- Implement transport-level security (delegated to Middleware)
- Make direct database calls (use repositories)

---

## Folder & File Structure

```
src/domains/auth/
├── auth.service.js         # Authentication business logic
├── auth.controller.js      # HTTP request handling
├── auth.routes.js          # Route definitions
├── auth.validation.js      # Input validation schemas
├── strategies/             # Authentication strategies (extensible)
│   ├── local.strategy.js   # Email/password authentication
│   └── oauth.strategy.js   # OAuth providers (future)
└── events/
    └── auth.events.js      # Authentication events
```

---

## Data Structures Used

### 1. Credential Pair (Tuple)
**Purpose:** Encapsulate login credentials as a unit

```javascript
// DSA Concept: Tuple/Pair data structure
// Ensures atomicity of credential handling

class Credentials {
  constructor(identifier, secret) {
    this.identifier = identifier;  // email or username
    this.secret = secret;          // password
    Object.freeze(this);           // Immutable
  }
}

// Usage
const creds = new Credentials(req.body.email, req.body.password);
```

### 2. Token Pair Response
**Purpose:** Atomic response containing both tokens

```javascript
// DSA Concept: Composite data structure
const tokenPair = {
  accessToken: 'eyJhbG...',   // Short-lived (15 min)
  refreshToken: 'dGhpcyB...',  // Long-lived (7 days)
  expiresIn: 900,              // Access token TTL in seconds
  tokenType: 'Bearer',
};
```

### 3. State Machine for Password Reset

```
DSA Concept: Finite State Machine (FSM)

States:
┌──────────────┐    request     ┌──────────────┐
│    NONE      │ ─────────────> │   PENDING    │
└──────────────┘                └──────────────┘
       ▲                              │
       │                              │ validate token
       │ expire                       ▼
       │                        ┌──────────────┐
       └─────────────────────── │  VALIDATED   │
                                └──────────────┘
                                      │
                                      │ set password
                                      ▼
                                ┌──────────────┐
                                │  COMPLETED   │
                                └──────────────┘

Transitions stored in user document:
- passwordResetToken: Token hash (PENDING state indicator)
- passwordResetExpires: Expiration time
- null/expired: NONE or COMPLETED state
```

---

## Algorithms Involved

### 1. Registration Algorithm

```
ALGORITHM register(userData):
INPUT: { email, username, password, ...optional }
OUTPUT: { user, tokens } OR AuthError

1. VALIDATE input against schema (Joi/Zod)
2. NORMALIZE email (lowercase, trim)
3. CHECK uniqueness:
   a. Query email index (O(log n))
   b. Query username index (O(log n))
   c. IF exists → throw ConflictError
4. VALIDATE password strength (FSM - O(n))
5. HASH password (bcrypt - O(2^cost))
6. BEGIN transaction (if multi-doc):
   a. CREATE user document
   b. CREATE email verification token
   c. EMIT USER_REGISTERED event
7. COMMIT transaction
8. GENERATE token pair (see Token Module)
9. RETURN { user: UserDTO, tokens: TokenPair }

TIME COMPLEXITY: O(log n) for uniqueness + O(2^cost) for hashing
```

### 2. Login Algorithm

```
ALGORITHM login(credentials):
INPUT: { email, password }
OUTPUT: { user, tokens } OR AuthError

1. FIND user by email (O(log n) - B-Tree index)
2. IF not found:
   a. DELAY response by random 200-500ms (timing attack prevention)
   b. THROW InvalidCredentialsError
3. CHECK account lock status:
   a. IF isLocked → throw AccountLockedError(unlockTime)
4. COMPARE password with hash (bcrypt.compare - O(2^cost)):
   a. IF mismatch:
      - INCREMENT login attempts
      - IF attempts >= MAX → LOCK account
      - DELAY response (timing attack prevention)
      - THROW InvalidCredentialsError
5. RESET login attempts to 0
6. UPDATE lastLogin timestamp
7. GENERATE token pair
8. STORE refresh token (for rotation tracking)
9. EMIT USER_LOGGED_IN event
10. RETURN { user: UserDTO, tokens: TokenPair }

TIMING ATTACK MITIGATION:
- Constant-time comparison in bcrypt
- Random delays on failure
- Same error message for all failure cases
```

### 3. Token Refresh Algorithm

```
ALGORITHM refreshTokens(refreshToken):
INPUT: Refresh token string
OUTPUT: { newAccessToken, newRefreshToken } OR AuthError

1. VALIDATE refresh token signature (HMAC - O(1))
2. CHECK token in database/cache:
   a. EXISTS AND not revoked? → Continue
   b. ELSE → throw InvalidTokenError
3. EXTRACT userId from token payload
4. VERIFY user still active:
   a. FIND user by ID (O(log n))
   b. IF inactive/deleted → revoke all tokens, throw
5. IMPLEMENT rotation:
   a. MARK current refresh token as used
   b. GENERATE new refresh token
   c. STORE new refresh token
6. GENERATE new access token
7. RETURN new token pair

TOKEN ROTATION BENEFIT:
- Detects token reuse (potential theft)
- Limits damage window of compromised tokens
```

### 4. Logout Algorithm

```
ALGORITHM logout(accessToken, refreshToken, logoutAll = false):
INPUT: Current tokens, optional logoutAll flag
OUTPUT: Success confirmation

1. DECODE access token (no verification needed for blacklisting)
2. IF logoutAll:
   a. FIND all refresh tokens for user
   b. REVOKE all refresh tokens
   c. ADD all access tokens to blacklist (if tracking)
   d. EMIT LOGOUT_ALL event
3. ELSE:
   a. REVOKE single refresh token
   b. ADD access token to blacklist (until expiry)
4. RETURN { success: true }

BLACKLIST STRATEGY:
- Store in Redis for O(1) lookup
- TTL = remaining access token lifetime
- Memory efficient: only store JTI (JWT ID)
```

---

## Software Design Principles Applied

### 1. Single Responsibility Principle (SRP)
```javascript
// auth.service.js handles ONLY authentication orchestration
class AuthService {
  constructor(userService, tokenService, sessionService) {
    this.userService = userService;    // User operations
    this.tokenService = tokenService;  // Token generation
    this.sessionService = sessionService;  // Session tracking
  }
  
  // No direct DB access, no token generation logic
  async login(credentials) {
    const user = await this.userService.findByEmail(credentials.email);
    // ... validation
    const tokens = await this.tokenService.generatePair(user);
    await this.sessionService.create(user.id, tokens.refreshToken);
    return { user, tokens };
  }
}
```

### 2. Open/Closed Principle (OCP) - Strategy Pattern
```javascript
// Authentication strategies are pluggable

// Base strategy interface
class AuthStrategy {
  async authenticate(credentials) { throw new Error('Not implemented'); }
}

// Local strategy (email/password)
class LocalStrategy extends AuthStrategy {
  async authenticate({ email, password }) {
    // ... local authentication logic
  }
}

// OAuth strategy (extensible)
class OAuthStrategy extends AuthStrategy {
  constructor(provider) {
    super();
    this.provider = provider;
  }
  
  async authenticate(oauthCode) {
    // ... OAuth flow
  }
}

// New strategies added without modifying existing code
```

### 3. Dependency Inversion Principle (DIP)
```javascript
// High-level AuthController depends on abstraction (AuthService interface)
// Not concrete implementations

class AuthController {
  constructor(authService) {  // Injected
    this.authService = authService;
  }
  
  async login(req, res, next) {
    const result = await this.authService.login(req.validatedBody);
    res.json(result);
  }
}
```

---

## Security Principles Applied

### 1. Credential Security (OWASP A02:2021, A07:2021)

```javascript
// Never log credentials
const login = async (req, res) => {
  const { email, password } = req.body;
  
  // LOG SAFELY - exclude password
  logger.info('Login attempt', { email });  // NO password
  
  // Clear password from request after use
  req.body.password = undefined;
};

// Generic error messages
const AUTH_ERRORS = {
  INVALID: 'Invalid email or password',  // Same for both cases
  LOCKED: 'Account temporarily locked',
};
```

### 2. Brute Force Protection

```javascript
// Account lockout implementation
const MAX_ATTEMPTS = 5;
const LOCK_DURATION = 2 * 60 * 60 * 1000;  // 2 hours

async function handleFailedLogin(user) {
  user.loginAttempts += 1;
  
  if (user.loginAttempts >= MAX_ATTEMPTS) {
    user.lockUntil = new Date(Date.now() + LOCK_DURATION);
    // Emit alert for monitoring
    emit('ACCOUNT_LOCKED', { userId: user.id, ip: req.ip });
  }
  
  await user.save();
}
```

### 3. Timing Attack Prevention

```javascript
// Constant-time operations
const bcrypt = require('bcrypt');

async function verifyPassword(inputPassword, storedHash) {
  // bcrypt.compare is constant-time
  const isValid = await bcrypt.compare(inputPassword, storedHash);
  
  // Add random delay regardless of result
  await delay(200 + Math.random() * 300);
  
  return isValid;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
```

### 4. Token Security

```javascript
// Secure token delivery
const setCookieOptions = {
  httpOnly: true,      // No JavaScript access
  secure: true,        // HTTPS only
  sameSite: 'strict',  // CSRF protection
  path: '/api/auth',   // Limited scope
  maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days
};

res.cookie('refreshToken', tokens.refreshToken, setCookieOptions);
res.json({ accessToken: tokens.accessToken });  // Access token in body
```

---

## Implementation

### auth.service.js

```javascript
const { AppError } = require('../../shared/errors');
const { emitEvent, AUTH_EVENTS } = require('../../shared/events');

class AuthService {
  constructor(userRepository, tokenService, sessionService) {
    this.userRepository = userRepository;
    this.tokenService = tokenService;
    this.sessionService = sessionService;
  }

  /**
   * Register a new user
   */
  async register(userData) {
    // Check uniqueness
    const [emailExists, usernameExists] = await Promise.all([
      this.userRepository.emailExists(userData.email),
      this.userRepository.usernameExists(userData.username),
    ]);

    if (emailExists) {
      throw new AppError('Email already registered', 409, 'EMAIL_EXISTS');
    }
    if (usernameExists) {
      throw new AppError('Username already taken', 409, 'USERNAME_EXISTS');
    }

    // Hash password
    const passwordHash = await this.hashPassword(userData.password);

    // Create user
    const user = await this.userRepository.create({
      ...userData,
      password: undefined,  // Don't store plain password
      passwordHash,
    });

    // Generate tokens
    const tokens = await this.tokenService.generatePair(user);
    
    // Create session
    await this.sessionService.create(user.id, tokens.refreshToken);

    // Emit event for email verification, analytics, etc.
    emitEvent(AUTH_EVENTS.USER_REGISTERED, {
      userId: user.id,
      email: user.email,
      timestamp: new Date(),
    });

    return {
      user: this.toUserDTO(user),
      tokens,
    };
  }

  /**
   * Authenticate user with credentials
   */
  async login(credentials, metadata = {}) {
    const { email, password } = credentials;
    const { ip, userAgent } = metadata;

    // Find user with password hash
    const user = await this.userRepository.findByEmail(email, { includePassword: true });

    // User not found - delay to prevent timing attacks
    if (!user) {
      await this.randomDelay();
      throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
    }

    // Check if account is locked
    if (user.isLocked) {
      throw new AppError('Account temporarily locked', 423, 'ACCOUNT_LOCKED', {
        unlockAt: user.lockUntil,
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      await user.incrementLoginAttempts();
      await this.randomDelay();
      throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
    }

    // Reset login attempts on success
    if (user.loginAttempts > 0) {
      user.loginAttempts = 0;
      user.lockUntil = undefined;
    }
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
    const tokens = await this.tokenService.generatePair(user);
    
    // Create session
    await this.sessionService.create(user.id, tokens.refreshToken, { ip, userAgent });

    // Emit event
    emitEvent(AUTH_EVENTS.USER_LOGGED_IN, {
      userId: user.id,
      ip,
      userAgent,
      timestamp: new Date(),
    });

    return {
      user: this.toUserDTO(user),
      tokens,
    };
  }

  /**
   * Refresh authentication tokens
   */
  async refreshTokens(refreshToken) {
    // Validate and decode refresh token
    const payload = await this.tokenService.verifyRefreshToken(refreshToken);

    // Check session validity
    const session = await this.sessionService.findByToken(refreshToken);
    if (!session || session.isRevoked) {
      // Potential token reuse attack - revoke all sessions
      if (session && session.isUsed) {
        await this.sessionService.revokeAllForUser(payload.userId);
        emitEvent(AUTH_EVENTS.TOKEN_REUSE_DETECTED, { userId: payload.userId });
      }
      throw new AppError('Invalid refresh token', 401, 'INVALID_TOKEN');
    }

    // Get user
    const user = await this.userRepository.findById(payload.userId);
    if (!user || !user.isActive) {
      await this.sessionService.revokeByToken(refreshToken);
      throw new AppError('User not found or inactive', 401, 'USER_INACTIVE');
    }

    // Token rotation: mark current token as used, generate new pair
    await this.sessionService.markAsUsed(refreshToken);
    
    const newTokens = await this.tokenService.generatePair(user);
    await this.sessionService.create(user.id, newTokens.refreshToken);

    return newTokens;
  }

  /**
   * Logout user
   */
  async logout(refreshToken, logoutAll = false, userId = null) {
    if (logoutAll && userId) {
      await this.sessionService.revokeAllForUser(userId);
      emitEvent(AUTH_EVENTS.USER_LOGGED_OUT_ALL, { userId });
    } else if (refreshToken) {
      await this.sessionService.revokeByToken(refreshToken);
    }

    return { success: true };
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(email) {
    const user = await this.userRepository.findByEmail(email);
    
    // Always return success (prevent email enumeration)
    if (!user) {
      return { message: 'If email exists, reset instructions sent' };
    }

    // Generate reset token
    const resetToken = await this.tokenService.generateResetToken();
    const hashedToken = await this.hashToken(resetToken);

    // Store hashed token with expiry
    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000);  // 1 hour
    await user.save();

    // Emit event for email service
    emitEvent(AUTH_EVENTS.PASSWORD_RESET_REQUESTED, {
      userId: user.id,
      email: user.email,
      resetToken,  // Plain token for email
    });

    return { message: 'If email exists, reset instructions sent' };
  }

  /**
   * Reset password with token
   */
  async resetPassword(token, newPassword) {
    const hashedToken = await this.hashToken(token);

    const user = await this.userRepository.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      throw new AppError('Invalid or expired reset token', 400, 'INVALID_TOKEN');
    }

    // Update password
    const passwordHash = await this.hashPassword(newPassword);
    await this.userRepository.updatePassword(user.id, passwordHash);

    // Revoke all existing sessions
    await this.sessionService.revokeAllForUser(user.id);

    emitEvent(AUTH_EVENTS.PASSWORD_RESET_COMPLETED, { userId: user.id });

    return { message: 'Password reset successful' };
  }

  // Private helper methods
  async hashPassword(password) {
    const bcrypt = require('bcrypt');
    return bcrypt.hash(password, 12);
  }

  async hashToken(token) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async randomDelay() {
    const delay = 200 + Math.random() * 300;
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  toUserDTO(user) {
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
    };
  }
}

module.exports = AuthService;
```

### auth.controller.js

```javascript
const asyncHandler = require('../../shared/utils/asyncHandler');

class AuthController {
  constructor(authService) {
    this.authService = authService;
  }

  register = asyncHandler(async (req, res) => {
    const result = await this.authService.register(req.validatedBody);
    
    // Set refresh token as httpOnly cookie
    this.setRefreshTokenCookie(res, result.tokens.refreshToken);
    
    res.status(201).json({
      success: true,
      data: {
        user: result.user,
        accessToken: result.tokens.accessToken,
        expiresIn: result.tokens.expiresIn,
      },
    });
  });

  login = asyncHandler(async (req, res) => {
    const result = await this.authService.login(req.validatedBody, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    this.setRefreshTokenCookie(res, result.tokens.refreshToken);
    
    res.json({
      success: true,
      data: {
        user: result.user,
        accessToken: result.tokens.accessToken,
        expiresIn: result.tokens.expiresIn,
      },
    });
  });

  refreshToken = asyncHandler(async (req, res) => {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: { code: 'NO_TOKEN', message: 'Refresh token required' },
      });
    }

    const tokens = await this.authService.refreshTokens(refreshToken);
    
    this.setRefreshTokenCookie(res, tokens.refreshToken);
    
    res.json({
      success: true,
      data: {
        accessToken: tokens.accessToken,
        expiresIn: tokens.expiresIn,
      },
    });
  });

  logout = asyncHandler(async (req, res) => {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    const logoutAll = req.body.logoutAll || false;
    
    await this.authService.logout(refreshToken, logoutAll, req.user?.id);
    
    res.clearCookie('refreshToken', { path: '/api/auth' });
    
    res.json({
      success: true,
      message: logoutAll ? 'Logged out from all devices' : 'Logged out successfully',
    });
  });

  requestPasswordReset = asyncHandler(async (req, res) => {
    const result = await this.authService.requestPasswordReset(req.validatedBody.email);
    res.json({ success: true, message: result.message });
  });

  resetPassword = asyncHandler(async (req, res) => {
    const { token, password } = req.validatedBody;
    const result = await this.authService.resetPassword(token, password);
    res.json({ success: true, message: result.message });
  });

  // Private helper
  setRefreshTokenCookie(res, token) {
    const isProduction = process.env.NODE_ENV === 'production';
    
    res.cookie('refreshToken', token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'strict' : 'lax',
      path: '/api/auth',
      maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days
    });
  }
}

module.exports = AuthController;
```

---

## Request → Response Lifecycle

```
Login Request:
┌───────────────────────────────────────────────────────────────────────────────┐
│ 1. Request hits /api/auth/login                                               │
│ 2. Rate limiter check (Token Bucket)                                          │
│ 3. CORS validation                                                            │
│ 4. Input validation (Joi schema)                                              │
│ 5. AuthController.login() called                                              │
│ 6. AuthService.login() orchestrates:                                          │
│    a. Find user (UserRepository)                                              │
│    b. Verify password (bcrypt)                                                │
│    c. Generate tokens (TokenService)                                          │
│    d. Create session (SessionService)                                         │
│    e. Emit event (EventEmitter)                                               │
│ 7. Set httpOnly cookie for refresh token                                      │
│ 8. Return access token in response body                                       │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Edge Cases & Failure Handling

| Scenario | Handling | Error Code |
|----------|----------|------------|
| User not found | Generic error + delay | INVALID_CREDENTIALS |
| Wrong password | Increment attempts + delay | INVALID_CREDENTIALS |
| Account locked | Return unlock time | ACCOUNT_LOCKED |
| Inactive user | Reject authentication | USER_INACTIVE |
| Token reuse | Revoke all sessions, alert | INVALID_TOKEN |
| Expired refresh token | Clear cookie, force re-login | TOKEN_EXPIRED |
| Email enumeration attempt | Same response timing | - |

---

## Scalability & Future Extension

### OAuth Integration
```javascript
// Add OAuth strategy without modifying core auth
class GoogleOAuthStrategy extends OAuthStrategy {
  async authenticate(code) {
    const googleUser = await this.verifyGoogleToken(code);
    return this.userService.findOrCreate({
      email: googleUser.email,
      provider: 'google',
      providerId: googleUser.id,
    });
  }
}
```

### Multi-Factor Authentication
```javascript
// MFA as additional step in login flow
async login(credentials, mfaCode) {
  const user = await this.validateCredentials(credentials);
  
  if (user.mfaEnabled) {
    if (!mfaCode) {
      return { requiresMfa: true, tempToken: generateTempToken(user) };
    }
    await this.mfaService.verify(user.id, mfaCode);
  }
  
  return this.completeLogin(user);
}
```

---

## Testing Boundaries

### Unit Tests
- Password validation algorithm
- Token generation
- Error response formatting

### Integration Tests
- Full login flow
- Account lockout
- Token refresh rotation

```javascript
describe('AuthService', () => {
  describe('login', () => {
    it('should lock account after 5 failed attempts', async () => {
      const user = await createTestUser();
      
      for (let i = 0; i < 5; i++) {
        await expect(
          authService.login({ email: user.email, password: 'wrong' })
        ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
      }
      
      await expect(
        authService.login({ email: user.email, password: 'wrong' })
      ).rejects.toMatchObject({ code: 'ACCOUNT_LOCKED' });
    });
  });
});
```
