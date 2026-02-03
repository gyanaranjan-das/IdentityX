# Security Engineering

## Threat Model

This document outlines threat modeling for the authentication system, covering attack vectors and mitigations for each auth flow.

---

## Authentication Flows - Threat Analysis

### 1. Registration Flow

**Attack Vectors:**
| Threat | Attack | Mitigation |
|--------|--------|------------|
| Account enumeration | Probe emails to check existence | Same response for all outcomes |
| Weak passwords | Dictionary attacks | Password strength validation |
| Spam accounts | Bot registrations | Rate limiting, CAPTCHA |
| Mass registration | Resource exhaustion | IP-based throttling |

**Mitigations Applied:**
```javascript
// Rate limit: 5 registrations per IP per hour
// Password: min 8 chars, upper, lower, number
// Response: Same timing for all outcomes
```

---

### 2. Login Flow

**Attack Vectors:**
| Threat | Attack | Mitigation |
|--------|--------|------------|
| Brute force | Password guessing | Account lockout after 5 attempts |
| Credential stuffing | Reused passwords | Rate limiting + monitoring |
| Timing attacks | Response time analysis | Constant-time comparison + delay |
| Session hijacking | Token theft | httpOnly cookies, short TTL |

**Mitigations Applied:**
```javascript
// Lockout: 2 hours after 5 failed attempts
// Timing: bcrypt.compare is constant-time
// Delays: Random 200-500ms on failure
// Tokens: 15-minute access, httpOnly refresh
```

---

### 3. Token Refresh Flow

**Attack Vectors:**
| Threat | Attack | Mitigation |
|--------|--------|------------|
| Token theft | XSS, network sniffing | httpOnly cookies, HTTPS |
| Replay attack | Reuse stolen token | Token rotation + family tracking |
| Token leakage | Logging, error messages | Never log tokens |

**Mitigations Applied:**
```javascript
// Rotation: New token on each refresh
// Family: Entire family revoked on reuse detection
// Storage: Hash tokens before storing
```

---

### 4. Password Reset Flow

**Attack Vectors:**
| Threat | Attack | Mitigation |
|--------|--------|------------|
| Email enumeration | Different responses | Same response regardless |
| Token brute force | Guess reset token | 64-byte random token |
| Token replay | Reuse after reset | Single-use, immediate invalidation |
| Link interception | MITM attack | HTTPS, short TTL (1 hour) |

---

## OWASP Top 10 Coverage

### A01: Broken Access Control
- RBAC with explicit permission checks
- Resource ownership validation
- Deny by default

### A02: Cryptographic Failures
- bcrypt for passwords (cost 12)
- HTTPS enforced
- Secrets in environment variables
- JWT with HMAC-SHA256

### A03: Injection
- Parameterized queries (Mongoose)
- Input sanitization (mongo-sanitize)
- Output encoding

### A04: Insecure Design
- Defense in depth (multiple layers)
- Fail securely (deny on error)
- Principle of least privilege

### A05: Security Misconfiguration
- Helmet.js security headers
- CORS whitelist
- Production error handling (no stack traces)

### A06: Vulnerable Components
- npm audit in CI
- Dependabot alerts
- Regular updates

### A07: Authentication Failures
- Account lockout
- Rate limiting
- Token rotation
- Secure password requirements

### A08: Software Integrity Failures
- CSRF protection (SameSite cookies)
- Subresource integrity
- Input validation

### A09: Security Logging Failures
- Audit logging for auth events
- Failed login tracking
- Anomaly detection alerts

### A10: SSRF
- URL validation
- Allowlist for external calls

---

## Security Headers (Helmet.js)

```javascript
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
```

---

## Incident Response

### Token Compromise
1. Revoke all user sessions
2. Force password reset
3. Audit recent activity
4. Alert user

### Database Breach
1. Passwords are hashed (bcrypt) - not reversible
2. Rotate JWT secrets
3. Invalidate all sessions
4. Notify affected users

---

## Security Checklist

- [x] Passwords hashed with bcrypt (cost 12)
- [x] Access tokens short-lived (15 min)
- [x] Refresh tokens httpOnly
- [x] HTTPS enforced
- [x] Rate limiting on auth endpoints
- [x] Account lockout implemented
- [x] CORS whitelist configured
- [x] Security headers set
- [x] Input sanitization
- [x] Audit logging enabled
