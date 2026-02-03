# IdentityX - Production-Grade Authentication System Architecture

## System Overview

IdentityX is a production-grade authentication platform built on the MERN stack (MongoDB, Express.js, React, Node.js) designed to handle thousands of concurrent users across multiple client applications.

### Architectural Philosophy

This system follows three core engineering pillars:

1. **Data Structures & Algorithms (DSA)** - Every component uses appropriate data structures for optimal time/space complexity
2. **Software Design Principles** - SOLID, DRY, KISS applied systematically
3. **Security Engineering** - Defense in depth with OWASP Top 10 compliance

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Web App   │  │  Mobile App │  │   Desktop   │  │ Third-Party │        │
│  │   (React)   │  │   (React    │  │    App      │  │    API      │        │
│  │             │  │   Native)   │  │             │  │   Consumer  │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
└─────────┼────────────────┼────────────────┼────────────────┼────────────────┘
          │                │                │                │
          └────────────────┴────────────────┴────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           API GATEWAY LAYER                                  │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         Rate Limiter                                  │   │
│  │                    (Token Bucket Algorithm)                           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      CORS / CSRF Protection                          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      Request Validation                               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          APPLICATION LAYER                                   │
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   Auth Domain   │    │   User Domain   │    │  Token/Session  │         │
│  │    Module       │    │     Module      │    │     Module      │         │
│  │                 │    │                 │    │                 │         │
│  │ • Register      │    │ • User CRUD     │    │ • JWT Create    │         │
│  │ • Login         │    │ • Password Mgmt │    │ • JWT Validate  │         │
│  │ • Logout        │    │ • Role Mgmt     │    │ • Token Rotate  │         │
│  │ • Refresh       │    │ • Permissions   │    │ • Session Mgmt  │         │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘         │
│           │                      │                      │                   │
│           └──────────────────────┴──────────────────────┘                   │
│                                  │                                          │
│                                  ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      Middleware Layer                                │   │
│  │   • Authentication Middleware                                        │   │
│  │   • Authorization Middleware (RBAC)                                  │   │
│  │   • Error Handling Middleware                                        │   │
│  │   • Request Logging Middleware                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DATA LAYER                                         │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                        MongoDB Cluster                                  │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │ │
│  │  │    Users     │  │   Sessions   │  │  Audit Logs  │                  │ │
│  │  │  Collection  │  │  Collection  │  │  Collection  │                  │ │
│  │  │              │  │              │  │              │                  │ │
│  │  │ Indexes:     │  │ Indexes:     │  │ Indexes:     │                  │ │
│  │  │ • email(1)   │  │ • userId(1)  │  │ • timestamp  │                  │ │
│  │  │ • username(1)│  │ • token(1)   │  │ • userId     │                  │ │
│  │  │ • role       │  │ • expiresAt  │  │ • action     │                  │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘                  │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         Redis Cache                                     │ │
│  │  • Rate Limit Counters (Sliding Window)                                │ │
│  │  • Token Blacklist (Hash Set)                                          │ │
│  │  • Session Cache                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Defense in Depth Model

```
Layer 1: Network Security
├── TLS 1.3 encryption
├── CORS restrictions
└── Rate limiting

Layer 2: Application Security
├── Input validation & sanitization
├── CSRF protection
├── Content Security Policy
└── Helmet.js security headers

Layer 3: Authentication Security
├── Password hashing (bcrypt with work factor)
├── JWT with short expiry
├── Refresh token rotation
└── Session binding

Layer 4: Authorization Security
├── RBAC with permission matrix
├── Least privilege enforcement
└── Resource-level access control

Layer 5: Data Security
├── Encrypted at rest
├── Audit logging
└── Data sanitization
```

---

## Documentation Index

### Backend Modules
| Module | Document | Purpose |
|--------|----------|---------|
| Configuration | [01-configuration-module.md](./backend/01-configuration-module.md) | Environment & secrets management |
| Database | [02-database-module.md](./backend/02-database-module.md) | MongoDB connection & indexing |
| User Domain | [03-user-domain-module.md](./backend/03-user-domain-module.md) | User entity & RBAC modeling |
| Auth Domain | [04-auth-domain-module.md](./backend/04-auth-domain-module.md) | Auth workflows |
| Token & Session | [05-token-session-module.md](./backend/05-token-session-module.md) | JWT & session management |
| Security | [06-security-module.md](./backend/06-security-module.md) | Protection mechanisms |
| Middleware | [07-middleware-module.md](./backend/07-middleware-module.md) | Request processing pipeline |
| API Routing | [08-api-routing-module.md](./backend/08-api-routing-module.md) | Endpoint structure |

### Frontend Modules
| Module | Document | Purpose |
|--------|----------|---------|
| Auth UI | [01-auth-ui-module.md](./frontend/01-auth-ui-module.md) | Login/Register screens |
| State Management | [02-state-management-module.md](./frontend/02-state-management-module.md) | Auth state lifecycle |
| Route Protection | [03-route-protection-module.md](./frontend/03-route-protection-module.md) | Protected routing |
| API Communication | [04-api-communication-module.md](./frontend/04-api-communication-module.md) | HTTP client layer |

### Cross-Cutting Documentation
| Topic | Document | Purpose |
|-------|----------|---------|
| DSA Application | [dsa-application.md](./cross-cutting/dsa-application.md) | Algorithm usage |
| Security Engineering | [security-engineering.md](./cross-cutting/security-engineering.md) | Threat modeling |
| Testing Strategy | [testing-strategy.md](./cross-cutting/testing-strategy.md) | Test boundaries |

---

## Quick Reference: Principle Mapping

### SOLID Application

| Principle | Backend Application | Frontend Application |
|-----------|---------------------|---------------------|
| **S**ingle Responsibility | Each service handles one domain (UserService, AuthService, TokenService) | Each component has one purpose (LoginForm, TokenManager) |
| **O**pen/Closed | Strategy pattern for auth providers | Extensible validation rules |
| **L**iskov Substitution | Auth providers implement common interface | Form components implement common props |
| **I**nterface Segregation | Separate interfaces for read/write operations | Separate hooks for different concerns |
| **D**ependency Inversion | Services depend on abstractions (Repository pattern) | Components depend on service abstractions |

### DSA Application Summary

| Component | Data Structure | Algorithm | Complexity |
|-----------|---------------|-----------|------------|
| Token Blacklist | Hash Set | O(1) lookup | Space: O(n) |
| Rate Limiter | Sliding Window Counter | Token Bucket | O(1) operations |
| Password Validation | Finite State Machine | Sequential validation | O(n) |
| Session Management | Hash Map + TTL | LRU eviction | O(1) avg |
| Permission Check | Adjacency List (Graph) | BFS/DFS traversal | O(V + E) |
| Email Index | B-Tree (MongoDB) | Binary Search | O(log n) |

---

## Request Lifecycle

```
                                    Request Flow
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. INGRESS                                                                  │
│    • TLS termination                                                        │
│    • Rate limit check (Token Bucket)                                        │
│    • CORS validation                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. PRE-PROCESSING                                                           │
│    • Request parsing (express.json())                                       │
│    • Input sanitization (xss, mongo-sanitize)                               │
│    • Request validation (Joi/Zod schema)                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. AUTHENTICATION (if protected route)                                      │
│    • Extract JWT from Authorization header                                  │
│    • Validate token signature (HMAC-SHA256)                                 │
│    • Check token blacklist (O(1) Hash lookup)                               │
│    • Attach user to request context                                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. AUTHORIZATION (if role-protected)                                        │
│    • Extract required permissions from route metadata                       │
│    • Fetch user roles and permissions                                       │
│    • Permission matrix lookup (O(1))                                        │
│    • Grant or deny access                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. BUSINESS LOGIC                                                           │
│    • Controller receives validated request                                  │
│    • Service layer processes business rules                                 │
│    • Repository layer handles data access                                   │
│    • Transactions for multi-document operations                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. RESPONSE                                                                 │
│    • Standardized response format                                           │
│    • Security headers (Helmet.js)                                           │
│    • Audit logging (async, non-blocking)                                    │
│    • Response compression (if applicable)                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure Overview

```
IdentityX/
├── backend/
│   ├── src/
│   │   ├── config/              # Configuration module
│   │   │   ├── index.js         # Config aggregation
│   │   │   ├── database.js      # DB connection config
│   │   │   ├── jwt.js           # JWT settings
│   │   │   └── security.js      # Security settings
│   │   │
│   │   ├── domains/             # Domain-driven modules
│   │   │   ├── user/
│   │   │   │   ├── user.model.js
│   │   │   │   ├── user.service.js
│   │   │   │   ├── user.repository.js
│   │   │   │   ├── user.controller.js
│   │   │   │   ├── user.routes.js
│   │   │   │   └── user.validation.js
│   │   │   │
│   │   │   └── auth/
│   │   │       ├── auth.service.js
│   │   │       ├── auth.controller.js
│   │   │       ├── auth.routes.js
│   │   │       └── auth.validation.js
│   │   │
│   │   ├── infrastructure/      # Cross-cutting infrastructure
│   │   │   ├── database/
│   │   │   │   ├── connection.js
│   │   │   │   └── migrations/
│   │   │   │
│   │   │   ├── security/
│   │   │   │   ├── rateLimiter.js
│   │   │   │   ├── bruteForce.js
│   │   │   │   └── sanitizer.js
│   │   │   │
│   │   │   └── token/
│   │   │       ├── jwt.service.js
│   │   │       ├── refresh.service.js
│   │   │       └── blacklist.service.js
│   │   │
│   │   ├── middleware/          # Express middleware
│   │   │   ├── auth.middleware.js
│   │   │   ├── rbac.middleware.js
│   │   │   ├── error.middleware.js
│   │   │   └── logging.middleware.js
│   │   │
│   │   ├── shared/              # Shared utilities
│   │   │   ├── errors/
│   │   │   ├── validators/
│   │   │   └── utils/
│   │   │
│   │   └── app.js               # Express app setup
│   │
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── e2e/
│   │
│   └── server.js                # Server entry point
│
├── frontend/
│   ├── src/
│   │   ├── features/            # Feature-based modules
│   │   │   └── auth/
│   │   │       ├── components/
│   │   │       ├── hooks/
│   │   │       ├── services/
│   │   │       └── store/
│   │   │
│   │   ├── shared/              # Shared components
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   └── utils/
│   │   │
│   │   ├── routes/              # Route definitions
│   │   │   ├── ProtectedRoute.jsx
│   │   │   └── PublicRoute.jsx
│   │   │
│   │   ├── services/            # API services
│   │   │   ├── api.js
│   │   │   └── tokenManager.js
│   │   │
│   │   └── App.jsx
│   │
│   └── tests/
│
└── docs/                        # This documentation
```

---

## Next Steps

1. Review each module document for detailed specifications
2. Implement modules in dependency order:
   - Configuration → Database → User Domain → Auth Domain → Token → Security → Middleware → Routes
3. Frontend implementation follows backend API availability
4. Integration testing at each module completion
