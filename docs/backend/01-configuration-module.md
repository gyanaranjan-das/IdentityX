# Configuration Module

## Module Purpose

Centralized configuration management that loads, validates, and provides type-safe access to all application settings. This module acts as a **single source of truth** for environment-dependent values.

---

## Responsibilities

### MUST Do:
- Load environment variables from `.env` files
- Validate all required configurations at startup (fail-fast)
- Provide strongly-typed configuration access
- Support multiple environments (development, staging, production)
- Mask sensitive values in logs

### MUST NOT Do:
- Store secrets in code
- Allow direct `process.env` access from other modules
- Permit runtime configuration changes for immutable settings
- Expose raw secret values in error messages

---

## Folder & File Structure

```
src/config/
├── index.js              # Configuration aggregation & export
├── env.validator.js      # Schema-based validation
├── database.config.js    # Database-specific settings
├── jwt.config.js         # JWT & token settings
├── security.config.js    # Security-related settings
├── app.config.js         # General app settings
└── constants.js          # Immutable application constants
```

---

## Data Structures Used

### 1. Frozen Object (Object.freeze)
**Purpose:** Ensure configuration immutability after validation

```javascript
// DSA Concept: Immutable Data Structure
// Prevents accidental modification, O(1) property access

const config = Object.freeze({
  jwt: Object.freeze({
    accessTokenExpiry: 900,  // 15 minutes
    refreshTokenExpiry: 604800, // 7 days
  }),
  // nested objects also frozen
});
```

**Complexity Analysis:**
- Property access: O(1)
- Memory: O(n) where n = number of config keys
- Freeze operation: O(n) one-time at startup

### 2. Map for Environment Mapping
**Purpose:** Efficient environment-to-config lookup

```javascript
// Alternative for complex multi-environment setups
const envConfigMap = new Map([
  ['development', { debug: true, logLevel: 'debug' }],
  ['production', { debug: false, logLevel: 'error' }],
  ['test', { debug: true, logLevel: 'silent' }],
]);

// O(1) lookup
const currentConfig = envConfigMap.get(process.env.NODE_ENV);
```

---

## Algorithms Involved

### 1. Schema Validation Algorithm (Fail-Fast Pattern)

```
ALGORITHM validateConfig(rawEnv):
INPUT: Raw environment variables object
OUTPUT: Validated config object OR throw ConfigError

1. DEFINE schema with required fields and types
2. FOR each field in schema:
   a. CHECK if field exists in rawEnv
   b. IF missing AND required:
      - ADD to missingFields list
   c. VALIDATE type/format
   d. IF invalid:
      - ADD to validationErrors list
3. IF missingFields.length > 0 OR validationErrors.length > 0:
   - THROW ConfigError with all errors (single error aggregation)
4. TRANSFORM values to correct types (parseInt, etc.)
5. RETURN frozen config object

TIME COMPLEXITY: O(n) where n = number of config fields
SPACE COMPLEXITY: O(n) for storing errors
```

### 2. Secret Masking Algorithm

```javascript
// Pattern: Selective Property Masking
function maskSecrets(config, secretKeys = ['password', 'secret', 'key', 'token']) {
  return JSON.parse(JSON.stringify(config), (key, value) => {
    if (secretKeys.some(sk => key.toLowerCase().includes(sk))) {
      return typeof value === 'string' ? '****' : value;
    }
    return value;
  });
}
// O(n * m) where n = keys, m = secretKeys.length
```

---

## Software Design Principles Applied

### 1. Single Responsibility Principle (SRP)
- Each config file handles ONE concern (database, jwt, security)
- Validation logic separated from loading logic

### 2. Open/Closed Principle (OCP)
- New configurations added via new config files without modifying existing code
- Validation rules extensible through schema expansion

```javascript
// Adding new config - doesn't modify existing code
// New file: src/config/cache.config.js
module.exports = {
  redis: {
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT, 10),
  },
};
```

### 3. Dependency Inversion Principle (DIP)
- Modules depend on config abstraction, not `process.env`
- Easy to mock in tests

```javascript
// Other modules receive config via injection
class AuthService {
  constructor(config) {  // Injected, not direct process.env access
    this.jwtConfig = config.jwt;
  }
}
```

### 4. KISS & DRY
- Simple frozen object pattern, no over-abstraction
- Common validation logic reused via schema

---

## Security Principles Applied

### 1. Secrets Management (OWASP A02:2021)
- Secrets loaded from environment, not hardcoded
- Support for external secret managers (AWS Secrets Manager, HashiCorp Vault)

```javascript
// Production secret loading pattern
async function loadSecrets() {
  if (process.env.NODE_ENV === 'production') {
    // Load from secret manager
    const secrets = await secretManager.getSecrets();
    return secrets;
  }
  // Development: use .env file
  return process.env;
}
```

### 2. Fail-Fast Validation
- Application refuses to start with invalid config
- Prevents runtime errors from misconfiguration

### 3. Least Privilege - Scoped Access
```javascript
// Export ONLY what each module needs
module.exports = {
  database: config.database,  // Only DB module gets this
  jwt: config.jwt,            // Only token module gets this
};
```

---

## Implementation

### env.validator.js

```javascript
const Joi = require('joi');

const envSchema = Joi.object({
  // Server
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .required(),
  PORT: Joi.number().default(3000),
  
  // Database
  MONGODB_URI: Joi.string().uri().required(),
  
  // JWT
  JWT_ACCESS_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_SECRET: Joi.string().min(32).required(),
  JWT_ACCESS_EXPIRY: Joi.string().default('15m'),
  JWT_REFRESH_EXPIRY: Joi.string().default('7d'),
  
  // Security
  BCRYPT_SALT_ROUNDS: Joi.number().min(10).max(14).default(12),
  RATE_LIMIT_WINDOW_MS: Joi.number().default(900000),
  RATE_LIMIT_MAX_REQUESTS: Joi.number().default(100),
  
  // CORS
  ALLOWED_ORIGINS: Joi.string().required(),
}).unknown(true);  // Allow other env vars

function validateEnv() {
  const { error, value } = envSchema.validate(process.env, {
    abortEarly: false,  // Collect ALL errors
  });
  
  if (error) {
    const errorMessages = error.details.map(d => d.message).join(', ');
    throw new Error(`Config validation error: ${errorMessages}`);
  }
  
  return value;
}

module.exports = { validateEnv };
```

### index.js

```javascript
const { validateEnv } = require('./env.validator');

// Validate at module load (fail-fast)
const env = validateEnv();

// Frozen, immutable configuration
const config = Object.freeze({
  env: env.NODE_ENV,
  port: env.PORT,
  
  database: Object.freeze({
    uri: env.MONGODB_URI,
    options: Object.freeze({
      maxPoolSize: 10,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 5000,
    }),
  }),
  
  jwt: Object.freeze({
    accessSecret: env.JWT_ACCESS_SECRET,
    refreshSecret: env.JWT_REFRESH_SECRET,
    accessExpiry: env.JWT_ACCESS_EXPIRY,
    refreshExpiry: env.JWT_REFRESH_EXPIRY,
  }),
  
  security: Object.freeze({
    bcryptSaltRounds: env.BCRYPT_SALT_ROUNDS,
    rateLimit: Object.freeze({
      windowMs: env.RATE_LIMIT_WINDOW_MS,
      maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
    }),
    corsOrigins: env.ALLOWED_ORIGINS.split(','),
  }),
});

module.exports = config;
```

---

## Request → Response Lifecycle

```
Application Startup:
┌───────────────────────────────────────────────────────────────┐
│ 1. require('./config') triggers module load                  │
│ 2. validateEnv() validates ALL environment variables         │
│ 3. IF validation fails → throw Error, process exits          │
│ 4. IF success → return frozen config object                  │
│ 5. Config available to all dependent modules                 │
└───────────────────────────────────────────────────────────────┘

Runtime Usage:
┌───────────────────────────────────────────────────────────────┐
│ Module imports config → accesses needed properties → O(1)    │
│ Example: const { jwt } = require('../config');               │
│          const expiry = jwt.accessExpiry;                    │
└───────────────────────────────────────────────────────────────┘
```

---

## Edge Cases & Failure Handling

| Scenario | Handling | Principle |
|----------|----------|-----------|
| Missing required env var | Fail-fast: throw at startup | Defense in Depth |
| Invalid type (e.g., PORT="abc") | Joi validation catches, throws | Input Validation |
| Empty secret | Min-length validation fails | Security |
| Config mutation attempt | Object.freeze prevents | Immutability |
| Unknown NODE_ENV | Joi `.valid()` rejects | Whitelist approach |

---

## Scalability & Future Extension

### Adding New Configuration

1. Add to `.env.example` as documentation
2. Add to Joi schema in `env.validator.js`
3. Add to config object in `index.js`
4. No existing code changes required (OCP)

### Environment-Specific Overrides

```javascript
// Support for environment-specific config files
// config/development.js, config/production.js
const baseConfig = require('./base');
const envConfig = require(`./${process.env.NODE_ENV}`);

module.exports = Object.freeze({
  ...baseConfig,
  ...envConfig,
});
```

### Secret Manager Integration

```javascript
// Future: Vault integration
class SecretsProvider {
  async load() { /* abstract */ }
}

class EnvSecretsProvider extends SecretsProvider {
  async load() { return process.env; }
}

class VaultSecretsProvider extends SecretsProvider {
  async load() { /* fetch from Vault */ }
}

// Factory pattern for provider selection
```

---

## Testing Boundaries

### Unit Tests
- Validation schema correctness
- Error message formatting
- Secret masking

### Integration Tests
- Full config loading with test `.env`
- Failure scenarios (missing vars)

```javascript
// Example test
describe('Config Module', () => {
  it('should throw on missing JWT_ACCESS_SECRET', () => {
    delete process.env.JWT_ACCESS_SECRET;
    expect(() => require('./config')).toThrow('JWT_ACCESS_SECRET');
  });
});
```
