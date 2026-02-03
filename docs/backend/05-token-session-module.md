# Token & Session Module

## Module Purpose

Implement secure JWT-based authentication with access/refresh token management, token rotation for enhanced security, and session tracking for multi-device support.

---

## Responsibilities

### MUST Do:
- Generate cryptographically secure JWT access tokens
- Generate and rotate refresh tokens
- Validate token signatures and claims
- Maintain token blacklist for revocation
- Track active sessions per user

### MUST NOT Do:
- Store user passwords
- Handle authentication business logic
- Make authorization decisions

---

## Data Structures Used

### 1. JWT Structure
```
Token Format: header.payload.signature

Payload Claims:
{
  "sub": "user_id",        // Subject
  "iat": 1706900000,       // Issued at
  "exp": 1706900900,       // Expires (15 min)
  "jti": "unique_id",      // JWT ID for revocation
  "type": "access",        // Token type
  "role": "user"           // User role
}
```

### 2. Token Blacklist (Hash Set with TTL)
```
DSA: Hash Set for O(1) lookup with automatic expiration

Redis Key: "blacklist:{jti}"
Operations: O(1) add, O(1) lookup
```

### 3. Session Document
```javascript
{
  userId: ObjectId,
  tokenFamily: "uuid",         // For rotation tracking
  refreshToken: "hashed",      // SHA-256 hash
  isRevoked: false,
  isUsed: false,               // Rotation detection
  expiresAt: Date,             // TTL index
}
```

---

## Algorithms

### JWT Generation
```
1. Generate unique JTI (uuid)
2. Set expiry (15 min access, 7 days refresh)
3. Sign with HMAC-SHA256
4. Return token string
```

### Token Rotation (Theft Detection)
```
1. Validate current refresh token
2. Check session status
3. IF session.isUsed → revoke entire family (theft detected)
4. Mark current as used
5. Generate new pair
6. Create new session (same family)
```

---

## Security Principles

### Key Management
```javascript
const secrets = {
  access: process.env.JWT_ACCESS_SECRET,
  refresh: process.env.JWT_REFRESH_SECRET,
};
```

### Token Storage
```javascript
// Hash refresh tokens before storage
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update(token).digest('hex');
```

---

## Implementation

### jwt.service.js

```javascript
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

class JwtService {
  constructor(blacklistService) {
    this.blacklistService = blacklistService;
    this.accessSecret = process.env.JWT_ACCESS_SECRET;
    this.refreshSecret = process.env.JWT_REFRESH_SECRET;
  }

  generateAccessToken(user) {
    const jti = uuidv4();
    const expiresIn = 900;

    const token = jwt.sign(
      { sub: user.id, type: 'access', role: user.role, jti },
      this.accessSecret,
      { algorithm: 'HS256', expiresIn, issuer: 'identityx' }
    );

    return { token, jti, expiresIn };
  }

  generateRefreshToken(user) {
    const jti = uuidv4();
    const expiresIn = 604800;

    const token = jwt.sign(
      { sub: user.id, type: 'refresh', jti },
      this.refreshSecret,
      { algorithm: 'HS256', expiresIn, issuer: 'identityx' }
    );

    return { token, jti, expiresIn };
  }

  generatePair(user) {
    const access = this.generateAccessToken(user);
    const refresh = this.generateRefreshToken(user);
    return {
      accessToken: access.token,
      refreshToken: refresh.token,
      expiresIn: access.expiresIn,
      tokenType: 'Bearer',
    };
  }

  async validateAccessToken(token) {
    const payload = jwt.verify(token, this.accessSecret, {
      algorithms: ['HS256'],
      issuer: 'identityx',
    });

    if (await this.blacklistService.has(payload.jti)) {
      throw new Error('Token revoked');
    }
    return payload;
  }
}

module.exports = JwtService;
```

### blacklist.service.js

```javascript
class BlacklistService {
  constructor(redisClient = null) {
    this.redis = redisClient;
    this.memoryStore = new Map();
  }

  async add(jti, ttl) {
    if (this.redis) {
      await this.redis.set(`blacklist:${jti}`, '1', 'EX', ttl);
    } else {
      this.memoryStore.set(jti, Date.now() + ttl * 1000);
    }
  }

  async has(jti) {
    if (this.redis) {
      return (await this.redis.exists(`blacklist:${jti}`)) === 1;
    }
    const expiry = this.memoryStore.get(jti);
    if (!expiry) return false;
    if (expiry < Date.now()) {
      this.memoryStore.delete(jti);
      return false;
    }
    return true;
  }
}

module.exports = BlacklistService;
```

### session.service.js

```javascript
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class SessionService {
  constructor(sessionRepository) {
    this.sessionRepository = sessionRepository;
  }

  async create(userId, refreshToken, metadata = {}) {
    return this.sessionRepository.create({
      userId,
      refreshToken: this.hashToken(refreshToken),
      tokenFamily: uuidv4(),
      ...metadata,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
  }

  async findByToken(refreshToken) {
    return this.sessionRepository.findByToken(this.hashToken(refreshToken));
  }

  async markAsUsed(refreshToken) {
    await this.sessionRepository.updateByToken(
      this.hashToken(refreshToken),
      { isUsed: true }
    );
  }

  async revokeFamily(tokenFamily) {
    await this.sessionRepository.revokeFamily(tokenFamily);
  }

  hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}

module.exports = SessionService;
```

---

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Expired token | Return 401, client refreshes |
| Token reuse | Revoke family, force re-auth |
| Blacklisted token | Return 401 |
| Invalid signature | Return 401 |

---

## Testing

```javascript
describe('TokenService', () => {
  it('should detect token reuse', async () => {
    const tokens = await authService.login(creds);
    await authService.refreshTokens(tokens.refreshToken);
    
    // Reuse old token - should fail
    await expect(
      authService.refreshTokens(tokens.refreshToken)
    ).rejects.toThrow('TOKEN_REUSE');
  });
});
```
