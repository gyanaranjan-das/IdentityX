# Middleware Layer Module

## Module Purpose

Implement the request processing pipeline with authentication verification, role-based authorization, and centralized error handling. Middleware executes in sequence, forming a Chain of Responsibility pattern.

---

## Responsibilities

### MUST Do:
- Authenticate requests via JWT validation
- Authorize based on roles and permissions
- Handle errors consistently
- Log requests for audit trail
- Transform request/response data

### MUST NOT Do:
- Contain business logic
- Access database directly (use services)
- Leak stack traces in production
- Skip middleware chain without reason

---

## Data Structures

### 1. Middleware Chain (Linked List)
```
DSA: Chain of Responsibility Pattern

Request → [CORS] → [Helmet] → [RateLimit] → [Auth] → [RBAC] → [Handler] → Response
            │         │           │           │        │
            └─────────┴───────────┴───────────┴────────┘
                              Error Middleware
                                    │
                                    ▼
                              Error Response
```

### 2. Permission Cache (LRU Cache)
```javascript
// Cache user permissions after first lookup
const permissionCache = new LRU({
  max: 1000,
  ttl: 5 * 60 * 1000, // 5 minutes
});

// O(1) lookup after first request
```

---

## Implementation

### auth.middleware.js

```javascript
const { AppError } = require('../shared/errors');

function authenticate(jwtService) {
  return async (req, res, next) => {
    try {
      // Extract token from header
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        throw new AppError('No token provided', 401, 'NO_TOKEN');
      }

      const token = authHeader.split(' ')[1];
      
      // Validate token
      const payload = await jwtService.validateAccessToken(token);
      
      // Attach user to request
      req.user = {
        id: payload.sub,
        role: payload.role,
        tokenId: payload.jti,
      };
      
      next();
    } catch (error) {
      next(error);
    }
  };
}

// Optional auth - doesn't fail if no token
function optionalAuth(jwtService) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return next();
    }

    try {
      const token = authHeader.split(' ')[1];
      const payload = await jwtService.validateAccessToken(token);
      req.user = { id: payload.sub, role: payload.role };
    } catch {
      // Ignore errors for optional auth
    }
    next();
  };
}

module.exports = { authenticate, optionalAuth };
```

### rbac.middleware.js

```javascript
const { hasPermission, ROLES } = require('../domains/user/roles/permission.constants');
const { AppError } = require('../shared/errors');

// Require specific permission
function requirePermission(...requiredPermissions) {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'UNAUTHORIZED'));
    }

    const userRole = req.user.role;
    
    // Check if user has any of the required permissions
    const hasAccess = requiredPermissions.some(permission => 
      hasPermission(userRole, permission)
    );

    if (!hasAccess) {
      return next(new AppError('Insufficient permissions', 403, 'FORBIDDEN'));
    }

    next();
  };
}

// Require specific role(s)
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'UNAUTHORIZED'));
    }

    if (!allowedRoles.includes(req.user.role)) {
      return next(new AppError('Insufficient role', 403, 'FORBIDDEN'));
    }

    next();
  };
}

// Resource ownership check
function requireOwnership(getResourceUserId) {
  return async (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'UNAUTHORIZED'));
    }

    // Admins can access any resource
    if (req.user.role === ROLES.ADMIN || req.user.role === ROLES.SUPER_ADMIN) {
      return next();
    }

    const resourceUserId = await getResourceUserId(req);
    
    if (resourceUserId !== req.user.id) {
      return next(new AppError('Access denied', 403, 'OWNERSHIP_REQUIRED'));
    }

    next();
  };
}

module.exports = { requirePermission, requireRole, requireOwnership };
```

### error.middleware.js

```javascript
const { AppError } = require('../shared/errors');

function errorHandler(err, req, res, next) {
  // Default values
  let statusCode = err.statusCode || 500;
  let errorCode = err.code || 'INTERNAL_ERROR';
  let message = err.message || 'Something went wrong';
  let details = err.details || null;

  // Log error
  if (statusCode >= 500) {
    console.error('Server Error:', {
      message: err.message,
      stack: err.stack,
      url: req.url,
      method: req.method,
      userId: req.user?.id,
    });
  }

  // Handle specific error types
  if (err.name === 'ValidationError') {
    statusCode = 400;
    errorCode = 'VALIDATION_ERROR';
    details = Object.values(err.errors).map(e => e.message);
  }

  if (err.name === 'MongoServerError' && err.code === 11000) {
    statusCode = 409;
    errorCode = 'DUPLICATE_ERROR';
    message = 'Resource already exists';
  }

  if (err.name === 'CastError') {
    statusCode = 400;
    errorCode = 'INVALID_ID';
    message = 'Invalid resource ID';
  }

  // Hide stack trace in production
  const isDevelopment = process.env.NODE_ENV === 'development';

  res.status(statusCode).json({
    success: false,
    error: {
      code: errorCode,
      message,
      ...(details && { details }),
      ...(isDevelopment && { stack: err.stack }),
    },
  });
}

// 404 handler
function notFoundHandler(req, res, next) {
  next(new AppError(`Route ${req.originalUrl} not found`, 404, 'NOT_FOUND'));
}

module.exports = { errorHandler, notFoundHandler };
```

### logging.middleware.js

```javascript
const { v4: uuidv4 } = require('uuid');

function requestLogger(req, res, next) {
  req.requestId = uuidv4();
  req.startTime = Date.now();

  // Log request
  console.log({
    type: 'request',
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  });

  // Log response
  res.on('finish', () => {
    console.log({
      type: 'response',
      requestId: req.requestId,
      statusCode: res.statusCode,
      duration: Date.now() - req.startTime,
      userId: req.user?.id,
    });
  });

  next();
}

module.exports = { requestLogger };
```

---

## Request Lifecycle

```
┌──────────────────────────────────────────────────────────┐
│ 1. Request → requestLogger (assign requestId)           │
│ 2. helmet (security headers)                            │
│ 3. cors (origin validation)                             │
│ 4. rateLimiter (throttle check)                         │
│ 5. express.json (parse body)                            │
│ 6. sanitizeMiddleware (clean inputs)                    │
│ 7. authenticate (JWT validation) - if protected route   │
│ 8. requirePermission (RBAC) - if role-protected route   │
│ 9. Controller handler                                   │
│ 10. Response OR errorHandler                            │
└──────────────────────────────────────────────────────────┘
```

---

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Missing Authorization header | Return 401 |
| Malformed JWT | Return 401 with INVALID_TOKEN |
| Expired token | Return 401 with TOKEN_EXPIRED |
| Insufficient permissions | Return 403 |
| Async middleware error | Caught by error handler |

---

## Testing

```javascript
describe('Auth Middleware', () => {
  it('should reject requests without token', async () => {
    const res = await request(app).get('/api/users/me');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('NO_TOKEN');
  });

  it('should attach user to request with valid token', async () => {
    const res = await request(app)
      .get('/api/users/me')
      .set('Authorization', `Bearer ${validToken}`);
    expect(res.status).toBe(200);
  });
});
```
