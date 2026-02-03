# API Routing & Versioning Module

## Module Purpose

Define route structure with clear separation between public and protected endpoints, implement API versioning for backward compatibility, and organize routes by domain.

---

## Responsibilities

### MUST Do:
- Group routes by domain
- Apply appropriate middleware to route groups
- Version API endpoints
- Document routes for API consumers
- Validate request input at route level

### MUST NOT Do:
- Contain business logic in routes
- Mix authentication middleware with public routes
- Expose internal paths

---

## Data Structures

### Route Registry (Tree Structure)
```
DSA: Trie/Prefix Tree for route matching

/api
├── /v1
│   ├── /auth (public)
│   │   ├── POST /register
│   │   ├── POST /login
│   │   ├── POST /refresh
│   │   ├── POST /logout
│   │   └── POST /password-reset
│   │
│   ├── /users (protected)
│   │   ├── GET /me
│   │   ├── PATCH /me
│   │   └── GET /:id (admin)
│   │
│   └── /admin (admin only)
│       ├── GET /users
│       └── PATCH /users/:id
```

---

## Implementation

### routes/index.js

```javascript
const express = require('express');
const authRoutes = require('./auth.routes');
const userRoutes = require('./user.routes');
const adminRoutes = require('./admin.routes');

const router = express.Router();

// Health check (public)
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API v1 routes
router.use('/v1/auth', authRoutes);
router.use('/v1/users', userRoutes);
router.use('/v1/admin', adminRoutes);

module.exports = router;
```

### routes/auth.routes.js

```javascript
const express = require('express');
const { authLimiter } = require('../infrastructure/security/rateLimiter');
const { validate } = require('../middleware/validation.middleware');
const { authSchemas } = require('../domains/auth/auth.validation');

const router = express.Router();

module.exports = (authController) => {
  // All auth routes have stricter rate limiting
  router.use(authLimiter);

  // Public routes
  router.post('/register',
    validate(authSchemas.register),
    authController.register
  );

  router.post('/login',
    validate(authSchemas.login),
    authController.login
  );

  router.post('/refresh',
    authController.refreshToken
  );

  router.post('/logout',
    authController.logout
  );

  router.post('/password-reset/request',
    validate(authSchemas.requestReset),
    authController.requestPasswordReset
  );

  router.post('/password-reset/confirm',
    validate(authSchemas.confirmReset),
    authController.resetPassword
  );

  return router;
};
```

### routes/user.routes.js

```javascript
const express = require('express');
const { authenticate } = require('../middleware/auth.middleware');
const { requirePermission } = require('../middleware/rbac.middleware');
const { PERMISSIONS } = require('../domains/user/roles/permission.constants');
const { validate } = require('../middleware/validation.middleware');
const { userSchemas } = require('../domains/user/user.validation');

const router = express.Router();

module.exports = (userController, jwtService) => {
  // All user routes require authentication
  router.use(authenticate(jwtService));

  // Own profile routes
  router.get('/me', userController.getProfile);

  router.patch('/me',
    validate(userSchemas.updateProfile),
    userController.updateProfile
  );

  router.patch('/me/password',
    validate(userSchemas.changePassword),
    userController.changePassword
  );

  // View other users (requires permission)
  router.get('/:id',
    requirePermission(PERMISSIONS.READ_USERS),
    userController.getUserById
  );

  return router;
};
```

### routes/admin.routes.js

```javascript
const express = require('express');
const { authenticate } = require('../middleware/auth.middleware');
const { requireRole } = require('../middleware/rbac.middleware');
const { ROLES } = require('../domains/user/roles/permission.constants');

const router = express.Router();

module.exports = (adminController, jwtService) => {
  // All admin routes require authentication + admin role
  router.use(authenticate(jwtService));
  router.use(requireRole(ROLES.ADMIN, ROLES.SUPER_ADMIN));

  // User management
  router.get('/users', adminController.listUsers);
  router.get('/users/:id', adminController.getUser);
  router.patch('/users/:id', adminController.updateUser);
  router.delete('/users/:id', adminController.deactivateUser);

  // Session management
  router.get('/sessions', adminController.listSessions);
  router.delete('/sessions/:id', adminController.revokeSession);

  // Audit logs
  router.get('/audit', adminController.getAuditLogs);

  return router;
};
```

### validation.middleware.js

```javascript
const { AppError } = require('../shared/errors');

function validate(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const details = error.details.map(d => ({
        field: d.path.join('.'),
        message: d.message,
      }));

      return next(new AppError('Validation failed', 400, 'VALIDATION_ERROR', details));
    }

    req.validatedBody = value;
    next();
  };
}

function validateQuery(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.query, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const details = error.details.map(d => ({
        field: d.path.join('.'),
        message: d.message,
      }));

      return next(new AppError('Invalid query parameters', 400, 'VALIDATION_ERROR', details));
    }

    req.validatedQuery = value;
    next();
  };
}

module.exports = { validate, validateQuery };
```

---

## API Response Format

```javascript
// Success response
{
  "success": true,
  "data": { /* payload */ },
  "meta": {
    "page": 1,
    "limit": 20,
    "total": 100
  }
}

// Error response
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": [
      { "field": "email", "message": "Invalid email format" }
    ]
  }
}
```

---

## Versioning Strategy

```javascript
// v1 routes (current)
app.use('/api/v1', v1Routes);

// v2 routes (future)
app.use('/api/v2', v2Routes);

// Version header support
app.use((req, res, next) => {
  const version = req.headers['api-version'] || 'v1';
  req.apiVersion = version;
  next();
});
```

---

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Invalid route | 404 with NOT_FOUND code |
| Method not allowed | 405 response |
| Validation failure | 400 with field errors |
| Missing version | Default to latest stable |

---

## Testing

```javascript
describe('Auth Routes', () => {
  describe('POST /api/v1/auth/register', () => {
    it('should register new user', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'test@example.com', password: 'Secure123!' });
      
      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
    });

    it('should reject invalid email', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'invalid', password: 'Secure123!' });
      
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });
  });
});
```
