# User Domain Module

## Module Purpose

Model the User entity with proper password lifecycle management, implement Role-Based Access Control (RBAC) with fine-grained permissions, and provide a clean domain-driven interface for user operations.

---

## Responsibilities

### MUST Do:
- Define User entity schema with validation
- Implement secure password hashing and comparison
- Model roles and permissions with hierarchy support
- Provide repository pattern for data access
- Emit domain events for cross-cutting concerns

### MUST NOT Do:
- Store plain-text passwords
- Expose password hashes outside the domain
- Mix authentication logic with user management
- Allow role escalation without proper authorization

---

## Folder & File Structure

```
src/domains/user/
├── user.model.js           # Mongoose schema & model
├── user.repository.js      # Data access abstraction
├── user.service.js         # Business logic
├── user.controller.js      # HTTP request handling
├── user.routes.js          # Route definitions
├── user.validation.js      # Input validation schemas
├── user.dto.js             # Data Transfer Objects
├── roles/
│   ├── role.model.js       # Role schema
│   ├── permission.constants.js  # Permission definitions
│   └── rbac.service.js     # RBAC logic
└── events/
    └── user.events.js      # Domain events
```

---

## Data Structures Used

### 1. Mongoose Document (Hash Map)
**Purpose:** Efficient O(1) field access for user properties

```javascript
// DSA Concept: Hash Map with schema validation
// Each document is essentially a hash map with typed fields

const userDoc = {
  _id: ObjectId,        // O(1) lookup by primary key (B-Tree index)
  email: String,        // O(log n) lookup via B-Tree index
  passwordHash: String, // Never exposed outside domain
  role: String,         // Maps to permission set
  // ... other fields
};
```

### 2. Permission Matrix (2D Array/Graph)
**Purpose:** Efficient permission lookup and inheritance

```
DSA Concept: Adjacency List for Role Hierarchy + Permission Set

Role Hierarchy (DAG - Directed Acyclic Graph):
    super_admin
        │
    ┌───┴───┐
    ▼       ▼
  admin   moderator
    │       │
    └───┬───┘
        ▼
       user
        │
        ▼
      guest

Permission Matrix:
┌──────────────┬────────┬──────┬────────┬───────┐
│ Permission   │ Guest  │ User │ Admin  │ Super │
├──────────────┼────────┼──────┼────────┼───────┤
│ read:profile │   ✗    │  ✓   │   ✓    │   ✓   │
│ write:profile│   ✗    │  ✓   │   ✓    │   ✓   │
│ read:users   │   ✗    │  ✗   │   ✓    │   ✓   │
│ write:users  │   ✗    │  ✗   │   ✓    │   ✓   │
│ delete:users │   ✗    │  ✗   │   ✗    │   ✓   │
│ manage:roles │   ✗    │  ✗   │   ✗    │   ✓   │
└──────────────┴────────┴──────┴────────┴───────┘

Lookup Complexity: O(1) with pre-computed permission sets
```

### 3. Enum as Finite Set
**Purpose:** Bounded, type-safe role values

```javascript
// DSA Concept: Finite Set with O(1) membership check
const ROLES = Object.freeze({
  GUEST: 'guest',
  USER: 'user',
  MODERATOR: 'moderator',
  ADMIN: 'admin',
  SUPER_ADMIN: 'super_admin',
});

const roleSet = new Set(Object.values(ROLES));
// O(1) validation: roleSet.has(inputRole)
```

---

## Algorithms Involved

### 1. Password Hashing (bcrypt with Adaptive Cost)

```
ALGORITHM hashPassword(plainPassword):
INPUT: Plain text password
OUTPUT: Secure hash

1. GENERATE random salt (16 bytes)
2. SET cost = 12 (adjustable based on hardware)
3. APPLY bcrypt key derivation:
   a. Expand password using Blowfish cipher setup
   b. Iterate 2^cost times (4096 for cost=12)
   c. Combine with salt
4. RETURN "$2b$" + cost + "$" + salt + hash

TIME COMPLEXITY: O(2^cost) - intentionally slow
SPACE COMPLEXITY: O(1)

SECURITY: Cost factor makes brute force infeasible
- 1 hash attempt ≈ 200-300ms on modern CPU
- 10 billion passwords would take ~63 years
```

### 2. Permission Resolution Algorithm

```
ALGORITHM hasPermission(userId, requiredPermission):
INPUT: User ID, required permission string
OUTPUT: Boolean

1. FETCH user with role from cache/database
2. GET role's permission set (Map lookup - O(1))
3. IF role is SUPER_ADMIN:
   - RETURN true (bypass all checks)
4. CHECK direct permission:
   - IF permissionSet.has(requiredPermission):
     - RETURN true
5. CHECK resource-level permission (if applicable):
   - PARSE resource type and action from permission
   - IF user owns resource OR has admin access:
     - RETURN true
6. RETURN false

TIME COMPLEXITY: O(1) average case
SPACE COMPLEXITY: O(p) where p = unique permissions count
```

### 3. Password Strength Validation (Finite State Machine)

```
ALGORITHM validatePasswordStrength(password):
INPUT: Password string
OUTPUT: { valid: boolean, errors: string[] }

States tracked (each is binary):
- hasMinLength: password.length >= 8
- hasUppercase: /[A-Z]/.test(password)
- hasLowercase: /[a-z]/.test(password)
- hasNumber: /[0-9]/.test(password)
- hasSpecial: /[!@#$%^&*]/.test(password)

TRANSITION TABLE:
┌────────────┬───────────────────────────────────────┐
│   Input    │              Next State               │
├────────────┼───────────────────────────────────────┤
│ A-Z        │ hasUppercase = true                   │
│ a-z        │ hasLowercase = true                   │
│ 0-9        │ hasNumber = true                      │
│ !@#$%...   │ hasSpecial = true                     │
│ any        │ length++ → check hasMinLength         │
└────────────┴───────────────────────────────────────┘

ACCEPT STATE: All required states are true

TIME COMPLEXITY: O(n) single pass through password
```

---

## Software Design Principles Applied

### 1. Single Responsibility Principle (SRP)
```javascript
// Each class/file has ONE reason to change

// user.model.js - Only schema definition
const userSchema = new Schema({ /* ... */ });

// user.repository.js - Only data access
class UserRepository {
  findByEmail(email) { /* ... */ }
  create(userData) { /* ... */ }
}

// user.service.js - Only business logic
class UserService {
  async register(userData) { /* validation + orchestration */ }
}
```

### 2. Open/Closed Principle (OCP)
```javascript
// Adding new roles without modifying existing code

// permission.constants.js - Extend, don't modify
const PERMISSIONS = {
  ...BASE_PERMISSIONS,
  ...ADMIN_PERMISSIONS,
  ...SUPER_ADMIN_PERMISSIONS,
  // Add new permission sets here
};

// New role addition
ROLES.SUPPORT = 'support';
ROLE_PERMISSIONS.support = ['read:tickets', 'write:tickets'];
```

### 3. Liskov Substitution Principle (LSP)
```javascript
// All repository implementations are interchangeable

class UserRepository {
  async findByEmail(email) { /* MongoDB impl */ }
}

class MockUserRepository {
  async findByEmail(email) { /* In-memory impl for testing */ }
}

// Both can be used wherever UserRepository is expected
```

### 4. Interface Segregation Principle (ISP)
```javascript
// Separate interfaces for different concerns

// UserReader - read-only operations
class UserReader {
  findById(id) { }
  findByEmail(email) { }
}

// UserWriter - write operations
class UserWriter {
  create(userData) { }
  update(id, userData) { }
}

// Services use only what they need
class PublicProfileService {
  constructor(userReader) { /* Only needs read access */ }
}
```

### 5. Dependency Inversion Principle (DIP)
```javascript
// High-level modules don't depend on low-level modules

// Abstract repository interface
class IUserRepository {
  findByEmail(email) { throw new Error('Not implemented'); }
}

// Concrete implementation
class MongoUserRepository extends IUserRepository {
  findByEmail(email) { return User.findOne({ email }); }
}

// Service depends on abstraction
class UserService {
  constructor(userRepository) {  // IUserRepository injected
    this.userRepository = userRepository;
  }
}
```

---

## Security Principles Applied

### 1. Password Security (OWASP A07:2021)
```javascript
const userSchema = new Schema({
  passwordHash: {
    type: String,
    required: true,
    select: false,  // NEVER return in queries by default
  },
});

// Password is hashed before save
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.passwordHash = await bcrypt.hash(this.password, 12);
  this.password = undefined;  // Remove plain password
  next();
});
```

### 2. Least Privilege
```javascript
// Users get minimum required permissions
const DEFAULT_USER_PERMISSIONS = [
  'read:own_profile',
  'write:own_profile',
  // NO access to other users by default
];

// Principle: Deny by default, grant explicitly
function hasPermission(user, permission) {
  // Super admin bypass is intentional and audited
  if (user.role === ROLES.SUPER_ADMIN) {
    auditLog('super_admin_bypass', { user: user.id, permission });
    return true;
  }
  return getRolePermissions(user.role).includes(permission);
}
```

### 3. Defense in Depth - Multiple Validation Layers
```javascript
// Layer 1: Schema validation (Joi/Zod at controller)
// Layer 2: Mongoose schema validation
// Layer 3: Database constraints (unique index)
// Layer 4: Business logic validation (service)

// Each layer catches different types of invalid data
```

---

## Implementation

### user.model.js

```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { ROLES, DEFAULT_ROLE } = require('./roles/permission.constants');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
      message: 'Invalid email format',
    },
  },
  
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    validate: {
      validator: (v) => /^[a-zA-Z0-9_]+$/.test(v),
      message: 'Username can only contain letters, numbers, and underscores',
    },
  },
  
  passwordHash: {
    type: String,
    required: true,
    select: false,  // Never return in queries
  },
  
  role: {
    type: String,
    enum: Object.values(ROLES),
    default: DEFAULT_ROLE,
  },
  
  isActive: {
    type: Boolean,
    default: true,
  },
  
  isEmailVerified: {
    type: Boolean,
    default: false,
  },
  
  emailVerificationToken: {
    type: String,
    select: false,
  },
  
  emailVerificationExpires: {
    type: Date,
    select: false,
  },
  
  passwordResetToken: {
    type: String,
    select: false,
  },
  
  passwordResetExpires: {
    type: Date,
    select: false,
  },
  
  lastLogin: {
    type: Date,
  },
  
  loginAttempts: {
    type: Number,
    default: 0,
  },
  
  lockUntil: {
    type: Date,
  },
}, {
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform: (doc, ret) => {
      delete ret.passwordHash;
      delete ret.__v;
      return ret;
    },
  },
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Instance method: Compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

// Instance method: Increment login attempts
userSchema.methods.incrementLoginAttempts = async function() {
  const LOCK_TIME = 2 * 60 * 60 * 1000; // 2 hours
  const MAX_LOGIN_ATTEMPTS = 5;
  
  // Reset if lock has expired
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 },
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account if max attempts reached
  if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + LOCK_TIME };
  }
  
  return this.updateOne(updates);
};

// Static method: Hash password
userSchema.statics.hashPassword = async function(password) {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
};

// Index definitions (documented in database module)
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1, _id: -1 });

const User = mongoose.model('User', userSchema);

module.exports = User;
```

### permission.constants.js

```javascript
/**
 * Role-Based Access Control (RBAC) Constants
 * DSA: Finite Set for roles, HashMap for permission lookup
 */

const ROLES = Object.freeze({
  GUEST: 'guest',
  USER: 'user',
  MODERATOR: 'moderator',
  ADMIN: 'admin',
  SUPER_ADMIN: 'super_admin',
});

const DEFAULT_ROLE = ROLES.USER;

/**
 * Permission naming convention: <action>:<resource>
 * Actions: read, write, delete, manage
 * Resources: profile, users, roles, settings, audit
 */
const PERMISSIONS = Object.freeze({
  // Profile permissions
  READ_OWN_PROFILE: 'read:own_profile',
  WRITE_OWN_PROFILE: 'write:own_profile',
  
  // User management permissions
  READ_USERS: 'read:users',
  WRITE_USERS: 'write:users',
  DELETE_USERS: 'delete:users',
  
  // Role management permissions
  READ_ROLES: 'read:roles',
  MANAGE_ROLES: 'manage:roles',
  
  // System permissions
  READ_AUDIT: 'read:audit',
  MANAGE_SETTINGS: 'manage:settings',
});

/**
 * Permission sets per role
 * DSA: HashMap with role as key, Set of permissions as value
 * Lookup: O(1)
 */
const ROLE_PERMISSIONS = Object.freeze({
  [ROLES.GUEST]: new Set([]),
  
  [ROLES.USER]: new Set([
    PERMISSIONS.READ_OWN_PROFILE,
    PERMISSIONS.WRITE_OWN_PROFILE,
  ]),
  
  [ROLES.MODERATOR]: new Set([
    PERMISSIONS.READ_OWN_PROFILE,
    PERMISSIONS.WRITE_OWN_PROFILE,
    PERMISSIONS.READ_USERS,
  ]),
  
  [ROLES.ADMIN]: new Set([
    PERMISSIONS.READ_OWN_PROFILE,
    PERMISSIONS.WRITE_OWN_PROFILE,
    PERMISSIONS.READ_USERS,
    PERMISSIONS.WRITE_USERS,
    PERMISSIONS.READ_ROLES,
    PERMISSIONS.READ_AUDIT,
  ]),
  
  [ROLES.SUPER_ADMIN]: new Set([
    ...Object.values(PERMISSIONS),  // All permissions
  ]),
});

/**
 * Role hierarchy for permission inheritance
 * DSA: Directed Acyclic Graph represented as adjacency list
 */
const ROLE_HIERARCHY = Object.freeze({
  [ROLES.SUPER_ADMIN]: [ROLES.ADMIN],
  [ROLES.ADMIN]: [ROLES.MODERATOR],
  [ROLES.MODERATOR]: [ROLES.USER],
  [ROLES.USER]: [ROLES.GUEST],
  [ROLES.GUEST]: [],
});

/**
 * Check if role has permission
 * @param {string} role 
 * @param {string} permission 
 * @returns {boolean}
 */
function hasPermission(role, permission) {
  const permissions = ROLE_PERMISSIONS[role];
  if (!permissions) return false;
  
  // Super admin bypass
  if (role === ROLES.SUPER_ADMIN) return true;
  
  return permissions.has(permission);
}

/**
 * Get all permissions for a role (including inherited)
 * @param {string} role 
 * @returns {Set<string>}
 */
function getAllPermissions(role) {
  const allPermissions = new Set(ROLE_PERMISSIONS[role] || []);
  
  // BFS to get inherited permissions
  const queue = [...(ROLE_HIERARCHY[role] || [])];
  const visited = new Set([role]);
  
  while (queue.length > 0) {
    const currentRole = queue.shift();
    if (visited.has(currentRole)) continue;
    
    visited.add(currentRole);
    const rolePerms = ROLE_PERMISSIONS[currentRole] || [];
    rolePerms.forEach(p => allPermissions.add(p));
    
    const children = ROLE_HIERARCHY[currentRole] || [];
    queue.push(...children);
  }
  
  return allPermissions;
}

module.exports = {
  ROLES,
  DEFAULT_ROLE,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  ROLE_HIERARCHY,
  hasPermission,
  getAllPermissions,
};
```

### user.repository.js

```javascript
const User = require('./user.model');

/**
 * User Repository - Data Access Layer
 * Implements Repository Pattern for separation of concerns
 */
class UserRepository {
  /**
   * Find user by ID
   * @param {string} id 
   * @param {Object} options - { includePassword: boolean }
   * @returns {Promise<User|null>}
   */
  async findById(id, options = {}) {
    let query = User.findById(id);
    
    if (options.includePassword) {
      query = query.select('+passwordHash');
    }
    
    return query.exec();
  }

  /**
   * Find user by email
   * @param {string} email 
   * @param {Object} options 
   * @returns {Promise<User|null>}
   */
  async findByEmail(email, options = {}) {
    let query = User.findOne({ email: email.toLowerCase() });
    
    if (options.includePassword) {
      query = query.select('+passwordHash');
    }
    
    return query.exec();
  }

  /**
   * Find user by username
   * @param {string} username 
   * @returns {Promise<User|null>}
   */
  async findByUsername(username) {
    return User.findOne({ username }).exec();
  }

  /**
   * Create new user
   * @param {Object} userData 
   * @param {Object} options - { session: mongoose.Session }
   * @returns {Promise<User>}
   */
  async create(userData, options = {}) {
    const [user] = await User.create([userData], options);
    return user;
  }

  /**
   * Update user by ID
   * @param {string} id 
   * @param {Object} updateData 
   * @returns {Promise<User|null>}
   */
  async update(id, updateData) {
    return User.findByIdAndUpdate(
      id,
      { $set: updateData },
      { new: true, runValidators: true }
    ).exec();
  }

  /**
   * Update user password
   * @param {string} id 
   * @param {string} hashedPassword 
   * @returns {Promise<User|null>}
   */
  async updatePassword(id, hashedPassword) {
    return User.findByIdAndUpdate(
      id,
      {
        $set: {
          passwordHash: hashedPassword,
          passwordResetToken: undefined,
          passwordResetExpires: undefined,
        },
      },
      { new: true }
    ).exec();
  }

  /**
   * Check if email exists
   * @param {string} email 
   * @returns {Promise<boolean>}
   */
  async emailExists(email) {
    const count = await User.countDocuments({ email: email.toLowerCase() });
    return count > 0;
  }

  /**
   * Check if username exists
   * @param {string} username 
   * @returns {Promise<boolean>}
   */
  async usernameExists(username) {
    const count = await User.countDocuments({ username });
    return count > 0;
  }

  /**
   * Find users with pagination
   * Cursor-based pagination for consistent results
   * @param {Object} filter 
   * @param {Object} options - { limit, cursor, sortField }
   * @returns {Promise<{ users: User[], nextCursor: string|null }>}
   */
  async findMany(filter = {}, options = {}) {
    const { limit = 20, cursor, sortField = 'createdAt' } = options;
    
    let query = filter;
    
    // Cursor-based pagination (more efficient than skip for large datasets)
    if (cursor) {
      const cursorDoc = await User.findById(cursor);
      if (cursorDoc) {
        query = {
          ...filter,
          $or: [
            { [sortField]: { $lt: cursorDoc[sortField] } },
            {
              [sortField]: cursorDoc[sortField],
              _id: { $lt: cursor },
            },
          ],
        };
      }
    }
    
    const users = await User.find(query)
      .sort({ [sortField]: -1, _id: -1 })
      .limit(limit + 1)  // Fetch one extra to check if more exist
      .exec();
    
    const hasMore = users.length > limit;
    const resultUsers = hasMore ? users.slice(0, -1) : users;
    const nextCursor = hasMore ? resultUsers[resultUsers.length - 1]._id : null;
    
    return { users: resultUsers, nextCursor };
  }

  /**
   * Soft delete user
   * @param {string} id 
   * @returns {Promise<User|null>}
   */
  async softDelete(id) {
    return User.findByIdAndUpdate(
      id,
      { $set: { isActive: false, deletedAt: new Date() } },
      { new: true }
    ).exec();
  }
}

module.exports = new UserRepository();
```

---

## Request → Response Lifecycle

```
User Registration:
┌───────────────────────────────────────────────────────────────────────────────┐
│ 1. Controller receives validated request                                      │
│ 2. Service checks email/username uniqueness (O(log n) index lookup)           │
│ 3. Service hashes password (O(2^cost) intentional)                             │
│ 4. Repository creates user document                                            │
│ 5. Domain event emitted (USER_REGISTERED)                                      │
│ 6. Response with user DTO (password excluded)                                  │
└───────────────────────────────────────────────────────────────────────────────┘

Permission Check:
┌───────────────────────────────────────────────────────────────────────────────┐
│ 1. Middleware extracts user from JWT                                           │
│ 2. Get required permission from route metadata                                 │
│ 3. Lookup role permissions (O(1) HashMap)                                      │
│ 4. Check if permission exists in set (O(1))                                    │
│ 5. Grant or deny access                                                        │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Edge Cases & Failure Handling

| Scenario | Handling | Principle |
|----------|----------|-----------|
| Duplicate email | Unique index throws, return 409 Conflict | Database constraint |
| Weak password | Validation rejects before hashing | Fail fast |
| Account locked | Return 423 Locked with unlock time | Brute force protection |
| Role not found | Default to minimum permissions | Least privilege |
| User soft-deleted | Exclude from queries, allow recovery | Data retention |

---

## Scalability & Future Extension

### Adding New User Fields
```javascript
// Add to schema without breaking existing code
userSchema.add({
  phoneNumber: { type: String, sparse: true },
  twoFactorEnabled: { type: Boolean, default: false },
});
```

### Multi-Tenancy Support
```javascript
// Add tenant context
userSchema.add({
  tenantId: { type: mongoose.Types.ObjectId, ref: 'Tenant' },
});

// Compound index for tenant queries
userSchema.index({ tenantId: 1, email: 1 }, { unique: true });
```

### Social Login Integration
```javascript
// OAuth providers
userSchema.add({
  providers: [{
    name: { type: String, enum: ['google', 'github', 'linkedin'] },
    providerId: String,
    accessToken: { type: String, select: false },
  }],
});
```

---

## Testing Boundaries

### Unit Tests
- Password hashing/comparison
- Permission checking logic
- Validation schema

### Integration Tests
- User CRUD operations
- Unique constraint enforcement
- Account locking mechanism

```javascript
describe('UserService', () => {
  describe('register', () => {
    it('should hash password before storing', async () => {
      const userData = { email: 'test@example.com', password: 'SecurePass123!' };
      const user = await userService.register(userData);
      
      expect(user.passwordHash).not.toBe(userData.password);
      expect(user.passwordHash).toMatch(/^\$2b\$/);
    });
    
    it('should reject duplicate email', async () => {
      await userService.register({ email: 'test@example.com', password: 'Pass123!' });
      
      await expect(
        userService.register({ email: 'test@example.com', password: 'Pass456!' })
      ).rejects.toThrow('Email already exists');
    });
  });
});
```
