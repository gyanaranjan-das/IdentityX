# Security & Protection Module

## Module Purpose

Implement comprehensive security mechanisms including rate limiting, brute force protection, CSRF/CORS strategies, and input sanitization to protect against OWASP Top 10 vulnerabilities.

---

## Responsibilities

### MUST Do:
- Implement rate limiting with Token Bucket algorithm
- Protect against brute force attacks
- Configure CORS with whitelist
- Sanitize all user inputs
- Set security headers

### MUST NOT Do:
- Block legitimate traffic
- Leak security implementation details
- Store sensitive data in responses
- Allow CORS wildcards in production

---

## Data Structures

### 1. Token Bucket Rate Limiter
```
DSA: Token Bucket Algorithm

┌────────────────────────────────────────────┐
│         Token Bucket per IP/User           │
│  Capacity: 100 tokens                      │
│  Refill: 100 tokens / 15 minutes           │
├────────────────────────────────────────────┤
│  Request arrives:                          │
│    IF bucket.tokens > 0:                   │
│      bucket.tokens--                       │
│      ALLOW request                         │
│    ELSE:                                   │
│      REJECT with 429                       │
└────────────────────────────────────────────┘

Time Complexity: O(1) per request
Space Complexity: O(n) where n = unique clients
```

### 2. Sliding Window Counter
```
DSA: Sliding Window for accurate rate tracking

Window: Current + Previous window weighted average

current_count + (previous_count * overlap_percentage)

More accurate than fixed window, prevents burst at window edges.
```

### 3. CORS Whitelist Set
```javascript
// O(1) origin lookup
const allowedOrigins = new Set([
  'https://app.identityx.com',
  'https://admin.identityx.com',
]);

const isAllowed = allowedOrigins.has(origin);
```

---

## Security Principles Applied

### OWASP Top 10 Coverage

| Vulnerability | Protection |
|---------------|------------|
| A01 Broken Access Control | RBAC, resource ownership checks |
| A02 Cryptographic Failures | bcrypt, secure tokens, HTTPS |
| A03 Injection | Input sanitization, parameterized queries |
| A04 Insecure Design | Defense in depth, least privilege |
| A05 Security Misconfiguration | Helmet.js, strict CORS |
| A06 Vulnerable Components | npm audit, dependency scanning |
| A07 Auth Failures | Rate limiting, account lockout |
| A08 Integrity Failures | CSRF tokens, SRI |
| A09 Logging Failures | Audit logging, monitoring |
| A10 SSRF | URL validation, allowlists |

---

## Implementation

### rateLimiter.js

```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

// General API rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests, please try again later',
        retryAfter: Math.ceil(req.rateLimit.resetTime / 1000),
      },
    });
  },
});

// Strict limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 attempts per 15 minutes
  skipSuccessfulRequests: true, // Only count failures
  keyGenerator: (req) => `auth:${req.ip}:${req.body?.email || 'unknown'}`,
});

// Password reset limiter
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  keyGenerator: (req) => `reset:${req.ip}`,
});

module.exports = { apiLimiter, authLimiter, passwordResetLimiter };
```

### sanitizer.js

```javascript
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const mongoSanitize = require('express-mongo-sanitize');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Sanitize HTML content
function sanitizeHtml(dirty) {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
  });
}

// Sanitize object recursively
function sanitizeObject(obj) {
  if (typeof obj === 'string') {
    return sanitizeHtml(obj).trim();
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }
  if (obj && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, sanitizeObject(v)])
    );
  }
  return obj;
}

// Express middleware
function sanitizeMiddleware(req, res, next) {
  if (req.body) req.body = sanitizeObject(req.body);
  if (req.query) req.query = sanitizeObject(req.query);
  if (req.params) req.params = sanitizeObject(req.params);
  next();
}

module.exports = { sanitizeHtml, sanitizeObject, sanitizeMiddleware };
```

### cors.config.js

```javascript
const cors = require('cors');

const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',')
);

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  exposedHeaders: ['X-RateLimit-Remaining'],
  maxAge: 86400, // 24 hours
};

module.exports = cors(corsOptions);
```

### helmet.config.js

```javascript
const helmet = require('helmet');

const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
});

module.exports = helmetConfig;
```

---

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Distributed attack (multiple IPs) | User-based limiting + CAPTCHA |
| Legitimate high traffic | Whitelist trusted IPs |
| Rate limit header stripping | Multiple indicator checks |
| XSS in JSON response | Content-Type strict |

---

## Testing

```javascript
describe('RateLimiter', () => {
  it('should block after max attempts', async () => {
    for (let i = 0; i < 5; i++) {
      await request(app).post('/api/auth/login').send(invalidCreds);
    }
    
    const response = await request(app)
      .post('/api/auth/login')
      .send(invalidCreds);
    
    expect(response.status).toBe(429);
  });
});
```
