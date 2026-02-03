# DSA Application in Authentication System

## Overview

This document explicitly maps Data Structures and Algorithms concepts to their real-world usage in the authentication system. Each application is genuine and serves a performance or design purpose.

---

## Hash Tables / Maps

### 1. Token Blacklist (O(1) Lookup)
**Location:** `blacklist.service.js`

```javascript
// Redis SET for revoked tokens
// Key: jti (JWT ID), Value: "1"
await redis.set(`blacklist:${jti}`, '1', 'EX', ttl);
await redis.exists(`blacklist:${jti}`);  // O(1)
```

**Why:** Every authenticated request must check if token is revoked. O(1) lookup is essential for performance at scale.

### 2. Permission Mapping
**Location:** `permission.constants.js`

```javascript
const ROLE_PERMISSIONS = {
  admin: new Set(['read:users', 'write:users']),
  user: new Set(['read:profile']),
};

// O(1) permission check
ROLE_PERMISSIONS['admin'].has('read:users');
```

**Why:** Authorization checks happen on every protected request. Hash set provides instant lookup.

### 3. Session Storage
**Location:** `session.service.js`

```javascript
// MongoDB document indexed by token hash
// Lookup by hashed refresh token: O(log n) with B-Tree index
```

---

## B-Tree (Database Indexes)

### 1. Email Lookup
**Location:** `user.model.js`

```javascript
userSchema.index({ email: 1 }, { unique: true });
```

**Why:** Login queries by email. Without index: O(n) scan. With B-Tree: O(log n).

### 2. Session Token Lookup
**Location:** `session.model.js`

```javascript
sessionSchema.index({ refreshToken: 1 });
sessionSchema.index({ userId: 1 });
```

**Why:** Token refresh and "logout all" operations require efficient lookups.

---

## Queue (FIFO)

### 1. Request Queue During Token Refresh
**Location:** `api.js` (frontend)

```javascript
let failedQueue = [];

// Queue requests while refreshing
failedQueue.push({ resolve, reject });

// Process in order after refresh
failedQueue.forEach(({ resolve }) => resolve(newToken));
```

**Why:** Prevents race conditions when multiple requests hit 401 simultaneously. FIFO ensures fair processing.

---

## Sliding Window

### 1. Rate Limiting
**Location:** `rateLimiter.js`

```
Algorithm: Sliding Window Counter

Current window count + (Previous window count × overlap%)

Example at time 1:30 in 15-min window:
window_1 (0:00-0:15): 50 requests
window_2 (0:15-0:30): 40 requests
current_time: 1:30 (50% into window_2)

effective_count = 40 + (50 × 0.5) = 65
```

**Why:** More accurate than fixed window, prevents burst at window boundaries.

---

## Token Bucket

### 1. API Rate Limiting
**Location:** `rateLimiter.js`

```
Bucket Capacity: 100 tokens
Refill Rate: 100 tokens / 15 minutes

Each request consumes 1 token.
If bucket empty → 429 Too Many Requests
```

**Why:** Allows bursts while enforcing average rate. Better UX than hard limits.

---

## Finite State Machine

### 1. Password Reset Flow
**Location:** `auth.service.js`

```
States: NONE → PENDING → VALIDATED → COMPLETED

Transitions:
- request_reset: NONE → PENDING
- validate_token: PENDING → VALIDATED
- set_password: VALIDATED → COMPLETED
- token_expire: PENDING → NONE
```

**Why:** Prevents invalid state transitions (e.g., resetting password without valid token).

### 2. Form State (Frontend)
**Location:** `LoginForm.jsx`

```
States: IDLE → VALIDATING → SUBMITTING → SUCCESS | ERROR

Ensures clear user feedback and prevents double submission.
```

---

## Linked List / Tree

### 1. Token Family (Rotation Tracking)
**Location:** `session.service.js`

```
Token Chain:
login_token → refresh_1 → refresh_2 → refresh_3 (current)
                 ↓
             marked "used"

If refresh_1 is reused → theft detected → revoke entire family
```

**Why:** Detects stolen refresh tokens by tracking lineage.

---

## Directed Acyclic Graph (DAG)

### 1. Role Hierarchy
**Location:** `permission.constants.js`

```
super_admin
    │
    ├── admin
    │
    └── moderator
          │
          └── user
               │
               └── guest

BFS traversal for inherited permissions
```

**Why:** Higher roles inherit lower role permissions without duplication.

---

## Hashing Algorithms

### 1. Password Hashing (bcrypt)
**Location:** `user.model.js`

```javascript
// O(2^cost) intentionally slow
// cost = 12 → ~300ms per hash
await bcrypt.hash(password, 12);
```

**Why:** Prevents brute force. 10 billion attempts would take ~95 years.

### 2. Token Hashing (SHA-256)
**Location:** `session.service.js`

```javascript
// O(n) where n = input length (constant for tokens)
crypto.createHash('sha256').update(token).digest('hex');
```

**Why:** Don't store raw refresh tokens. Comparison on lookup.

---

## Time-To-Live (TTL) Index

### 1. Session Auto-Cleanup
**Location:** `indexes.js`

```javascript
{ expiresAt: 1 }, { expireAfterSeconds: 0 }
```

**Why:** Automatic cleanup without cron jobs. MongoDB handles expiration.

---

## Immutable Data Structures

### 1. Configuration Object
**Location:** `config/index.js`

```javascript
const config = Object.freeze({
  jwt: Object.freeze({
    accessExpiry: 900,
  }),
});
```

**Why:** Prevents accidental runtime modification of critical settings.

---

## Complexity Summary

| Component | Data Structure | Time Complexity | Space Complexity |
|-----------|----------------|-----------------|------------------|
| Token blacklist | Hash Set | O(1) lookup | O(k) active |
| Email lookup | B-Tree | O(log n) | O(n) |
| Rate limiter | Sliding Window | O(1) | O(1) per client |
| Request queue | Queue | O(1) enqueue/dequeue | O(q) pending |
| Password hash | bcrypt | O(2^cost) | O(1) |
| Permission check | Hash Set | O(1) | O(p) permissions |
| Role inheritance | DAG + BFS | O(V + E) | O(V) visited |
