# Database Module

## Module Purpose

Manage the complete MongoDB connection lifecycle, implement optimal indexing strategies, and provide a reliable data access layer with proper transaction support for multi-document operations.

---

## Responsibilities

### MUST Do:
- Establish and manage MongoDB connection pool
- Implement connection health monitoring and auto-reconnect
- Define database indexes for query optimization
- Provide transaction support for atomic operations
- Handle graceful shutdown on process termination

### MUST NOT Do:
- Expose raw MongoDB driver to application code
- Allow unindexed queries on large collections
- Ignore connection errors
- Perform blocking operations during connection lifecycle

---

## Folder & File Structure

```
src/infrastructure/database/
├── connection.js         # Connection manager
├── indexes.js            # Index definitions and creation
├── transaction.js        # Transaction utilities
├── healthCheck.js        # Connection health monitoring
└── migrations/           # Database migrations (if needed)
    └── README.md
```

---

## Data Structures Used

### 1. Connection Pool (Bounded Queue)
**MongoDB Driver Implementation:** Internal connection pool using bounded queue

```
DSA Concept: Bounded Queue / Object Pool Pattern

┌────────────────────────────────────────────────────────────┐
│                    Connection Pool                         │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                  │
│  │Conn1│ │Conn2│ │Conn3│ │Conn4│ │Conn5│ ... maxPoolSize  │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘                  │
│     │       │       │                                      │
│  [BUSY]  [IDLE]  [BUSY]                                    │
└────────────────────────────────────────────────────────────┘

Operations:
- Acquire connection: O(1) from idle pool
- Release connection: O(1) back to pool
- If pool exhausted: Request queued until connection available
```

**Configuration:**
```javascript
const poolConfig = {
  maxPoolSize: 10,    // Maximum connections
  minPoolSize: 2,     // Minimum idle connections (prevent cold starts)
  maxIdleTimeMS: 30000,  // Close idle connections after 30s
};
```

### 2. B-Tree Indexes
**Purpose:** All MongoDB indexes use B-Tree structure for efficient queries

```
DSA Concept: B-Tree (Balanced Tree)

Index on 'email' field:
                    ┌─────────────────┐
                    │  c@ex  │  m@ex  │
                    └────┬───┴───┬────┘
                   /     │       │     \
        ┌─────────┐  ┌─────────┐  ┌─────────┐
        │ a@ex    │  │ h@ex    │  │ z@ex    │
        │ b@ex    │  │ j@ex    │  │         │
        └─────────┘  └─────────┘  └─────────┘

Time Complexity:
- Search: O(log n)
- Insert: O(log n)
- Delete: O(log n)
- Range query: O(log n + k) where k = result size
```

### 3. TTL Index (Time-Based Expiration)
**Purpose:** Automatic session/token cleanup

```javascript
// DSA Concept: Lazy Deletion with Background Process
// MongoDB runs background job every 60 seconds to remove expired docs

db.sessions.createIndex(
  { "expiresAt": 1 },
  { expireAfterSeconds: 0 }  // Delete when expiresAt is reached
);

// Complexity: 
// - Insert: O(log n)
// - Automatic deletion: O(log n) per document, background process
```

---

## Algorithms Involved

### 1. Connection Retry Algorithm (Exponential Backoff)

```
ALGORITHM connectWithRetry(uri, options):
INPUT: MongoDB URI, connection options
OUTPUT: Connected mongoose instance OR throw Error

1. SET maxRetries = 5
2. SET baseDelay = 1000  // 1 second
3. SET currentRetry = 0

4. WHILE currentRetry < maxRetries:
   a. TRY:
      - await mongoose.connect(uri, options)
      - LOG "Connected successfully"
      - RETURN mongoose
   b. CATCH error:
      - currentRetry++
      - IF currentRetry >= maxRetries:
        - THROW ConnectionError("Max retries exceeded")
      - delay = baseDelay * (2 ^ currentRetry) + random(0, 1000)
      - LOG "Retry {currentRetry} in {delay}ms"
      - WAIT delay milliseconds
      - CONTINUE

TIME COMPLEXITY: O(maxRetries) worst case
DELAY PATTERN: 2s, 4s, 8s, 16s, 32s (with jitter)
```

### 2. Index Creation Strategy

```
ALGORITHM ensureIndexes():
INPUT: Collection and index definitions
OUTPUT: Indexes created/updated

1. FOR each collection in indexDefinitions:
   a. GET existing indexes
   b. FOR each required index:
      i. IF index exists with same spec:
         - SKIP
      ii. ELSE IF index exists with different spec:
         - DROP old index
         - CREATE new index
      iii. ELSE:
         - CREATE index
   c. LOG index creation results

NOTE: Use { background: true } in production for non-blocking creation
```

---

## Software Design Principles Applied

### 1. Single Responsibility Principle (SRP)
- `connection.js`: Only connection lifecycle
- `indexes.js`: Only index management
- `transaction.js`: Only transaction utilities

### 2. Open/Closed Principle (OCP)
- New collections added via new model files
- Index definitions extensible via configuration

```javascript
// indexes.js - easily extensible
const indexDefinitions = {
  users: [
    { fields: { email: 1 }, options: { unique: true } },
    { fields: { username: 1 }, options: { unique: true } },
    { fields: { role: 1 } },
  ],
  sessions: [
    { fields: { userId: 1 } },
    { fields: { token: 1 }, options: { unique: true } },
    { fields: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
  ],
  // Add new collections without modifying existing code
};
```

### 3. Dependency Inversion Principle (DIP)
- Application code depends on mongoose abstraction
- Easy to swap database in tests

```javascript
// Repository depends on abstraction
class UserRepository {
  constructor(model) {  // Model injected
    this.model = model;
  }
  
  async findByEmail(email) {
    return this.model.findOne({ email });
  }
}
```

---

## Security Principles Applied

### 1. Least Privilege Database Access
```javascript
// Use separate DB users for different operations
// Read-only user for reporting queries
// Read-write user for application

const connectionConfig = {
  readPreference: 'secondaryPreferred',  // Read from replicas when possible
  authSource: 'admin',
  authMechanism: 'SCRAM-SHA-256',
};
```

### 2. Injection Prevention (OWASP A03:2021)
```javascript
// Mongoose schema validation + sanitization
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
    validate: [isEmail, 'Invalid email'],
  },
});

// Never use string interpolation for queries
// BAD: db.users.find({ email: `${userInput}` })
// GOOD: db.users.find({ email: sanitizedInput })
```

### 3. Encrypted Connections
```javascript
const options = {
  ssl: process.env.NODE_ENV === 'production',
  sslValidate: true,
  sslCA: process.env.MONGODB_CA_CERT,
};
```

---

## Implementation

### connection.js

```javascript
const mongoose = require('mongoose');
const config = require('../../config');
const { createIndexes } = require('./indexes');

// Connection state tracking
let isConnected = false;

/**
 * Connect to MongoDB with retry logic
 * Uses exponential backoff for resilience
 */
async function connect(options = {}) {
  if (isConnected) {
    console.log('Using existing database connection');
    return mongoose;
  }

  const defaultOptions = {
    maxPoolSize: 10,
    minPoolSize: 2,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    family: 4,  // Use IPv4
  };

  const connectionOptions = { ...defaultOptions, ...options };

  return connectWithRetry(config.database.uri, connectionOptions);
}

async function connectWithRetry(uri, options, maxRetries = 5) {
  let currentRetry = 0;
  const baseDelay = 1000;

  while (currentRetry < maxRetries) {
    try {
      await mongoose.connect(uri, options);
      isConnected = true;
      
      console.log('MongoDB connected successfully');
      
      // Set up event handlers
      setupEventHandlers();
      
      // Create indexes after connection
      await createIndexes();
      
      return mongoose;
    } catch (error) {
      currentRetry++;
      
      if (currentRetry >= maxRetries) {
        console.error('Max connection retries exceeded');
        throw error;
      }

      // Exponential backoff with jitter
      const delay = baseDelay * Math.pow(2, currentRetry) + Math.random() * 1000;
      console.log(`Connection failed. Retry ${currentRetry}/${maxRetries} in ${Math.round(delay)}ms`);
      
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

function setupEventHandlers() {
  mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
    isConnected = false;
  });

  mongoose.connection.on('disconnected', () => {
    console.warn('MongoDB disconnected. Attempting reconnect...');
    isConnected = false;
  });

  mongoose.connection.on('reconnected', () => {
    console.log('MongoDB reconnected');
    isConnected = true;
  });
}

/**
 * Graceful shutdown
 */
async function disconnect() {
  if (!isConnected) return;
  
  try {
    await mongoose.connection.close();
    isConnected = false;
    console.log('MongoDB connection closed gracefully');
  } catch (error) {
    console.error('Error closing MongoDB connection:', error);
    throw error;
  }
}

// Handle process termination
process.on('SIGINT', async () => {
  await disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await disconnect();
  process.exit(0);
});

module.exports = {
  connect,
  disconnect,
  getConnection: () => mongoose.connection,
  isConnected: () => isConnected,
};
```

### indexes.js

```javascript
const mongoose = require('mongoose');

/**
 * Index definitions for all collections
 * DSA: B-Tree indexes for O(log n) lookups
 */
const indexDefinitions = {
  users: [
    // Unique email for login - most frequent query
    {
      fields: { email: 1 },
      options: { unique: true, background: true },
    },
    // Unique username for profile URLs
    {
      fields: { username: 1 },
      options: { unique: true, background: true },
    },
    // Role filtering for admin queries
    {
      fields: { role: 1 },
      options: { background: true },
    },
    // Compound index for paginated user lists
    {
      fields: { createdAt: -1, _id: -1 },
      options: { background: true },
    },
  ],
  
  refreshtokens: [
    // Token lookup for validation
    {
      fields: { token: 1 },
      options: { unique: true, background: true },
    },
    // User's tokens for logout all devices
    {
      fields: { userId: 1 },
      options: { background: true },
    },
    // TTL index for automatic cleanup
    {
      fields: { expiresAt: 1 },
      options: { expireAfterSeconds: 0, background: true },
    },
  ],
  
  auditlogs: [
    // Time-based queries
    {
      fields: { timestamp: -1 },
      options: { background: true },
    },
    // User activity lookup
    {
      fields: { userId: 1, timestamp: -1 },
      options: { background: true },
    },
    // Action type filtering
    {
      fields: { action: 1, timestamp: -1 },
      options: { background: true },
    },
  ],
};

/**
 * Create or verify indexes exist
 * Non-blocking with background: true
 */
async function createIndexes() {
  const db = mongoose.connection.db;
  
  for (const [collectionName, indexes] of Object.entries(indexDefinitions)) {
    try {
      const collection = db.collection(collectionName);
      
      for (const indexDef of indexes) {
        try {
          await collection.createIndex(indexDef.fields, indexDef.options);
          console.log(`Index created: ${collectionName}.${JSON.stringify(indexDef.fields)}`);
        } catch (error) {
          if (error.code === 85) {
            // Index already exists with different options - skip
            console.log(`Index exists with different options: ${collectionName}`);
          } else {
            throw error;
          }
        }
      }
    } catch (error) {
      console.error(`Error creating indexes for ${collectionName}:`, error);
    }
  }
}

module.exports = { createIndexes, indexDefinitions };
```

### transaction.js

```javascript
const mongoose = require('mongoose');

/**
 * Execute operations in a transaction
 * DSA Concept: Atomic operation guaranteeing ACID properties
 * 
 * @param {Function} operations - Async function receiving session
 * @returns {Promise<any>} Transaction result
 */
async function withTransaction(operations) {
  const session = await mongoose.startSession();
  
  try {
    session.startTransaction({
      readConcern: { level: 'snapshot' },
      writeConcern: { w: 'majority' },
    });

    const result = await operations(session);
    
    await session.commitTransaction();
    return result;
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
}

/**
 * Example usage for user registration with related data
 */
async function exampleTransactionUsage() {
  await withTransaction(async (session) => {
    // All operations use the same session
    const user = await User.create([{ email: 'user@example.com' }], { session });
    await Profile.create([{ userId: user[0]._id }], { session });
    await AuditLog.create([{ userId: user[0]._id, action: 'register' }], { session });
    
    return user[0];
  });
}

module.exports = { withTransaction };
```

---

## Request → Response Lifecycle

```
Application Startup:
┌───────────────────────────────────────────────────────────────────────────────┐
│ 1. Server.js calls database.connect()                                         │
│ 2. Connect with retry (exponential backoff if failure)                        │
│ 3. Set up event handlers for connection monitoring                            │
│ 4. Create/verify indexes in background                                        │
│ 5. Return connected mongoose instance                                         │
│ 6. Server begins accepting requests                                           │
└───────────────────────────────────────────────────────────────────────────────┘

Runtime Query:
┌───────────────────────────────────────────────────────────────────────────────┐
│ 1. Service calls repository method                                            │
│ 2. Repository uses mongoose model                                             │
│ 3. Query routed to indexed field → O(log n) lookup                            │
│ 4. Connection acquired from pool → O(1)                                       │
│ 5. Query executed                                                             │
│ 6. Connection returned to pool → O(1)                                         │
│ 7. Result returned to service                                                 │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Edge Cases & Failure Handling

| Scenario | Handling | Principle |
|----------|----------|-----------|
| Initial connection failure | Exponential backoff retry | Resilience |
| Connection drop during operation | Auto-reconnect, retry query | Fault Tolerance |
| Pool exhausted | Request queued until connection available | Backpressure |
| Index creation on production | `background: true` for non-blocking | Availability |
| Transaction conflict | Retry with jitter | Optimistic locking |
| Unindexed query | Log warning in development | Observability |

---

## Scalability & Future Extension

### Horizontal Scaling with Replica Sets
```javascript
const replicaSetOptions = {
  replicaSet: 'rs0',
  readPreference: 'secondaryPreferred',  // Read from replicas
  w: 'majority',  // Write acknowledged by majority
};
```

### Sharding Considerations
```javascript
// Shard key selection for users collection
// Option 1: Hashed _id for even distribution
db.users.createIndex({ _id: 'hashed' });

// Option 2: Compound key for locality (e.g., region-based)
db.users.createIndex({ region: 1, _id: 1 });
```

### Read/Write Splitting
```javascript
// Separate read and write connection pools
const readPool = mongoose.createConnection(config.database.readUri, {
  readPreference: 'secondary',
});

const writePool = mongoose.createConnection(config.database.writeUri, {
  readPreference: 'primary',
});
```

---

## Testing Boundaries

### Unit Tests
- Connection retry logic (mock mongoose.connect)
- Event handler setup

### Integration Tests
- Actual MongoDB connection (use Docker container)
- Index creation verification
- Transaction rollback scenarios

```javascript
describe('Database Module', () => {
  describe('Connection', () => {
    it('should retry connection on failure', async () => {
      // Mock mongoose.connect to fail twice then succeed
      const connectSpy = jest.spyOn(mongoose, 'connect')
        .mockRejectedValueOnce(new Error('Connection refused'))
        .mockRejectedValueOnce(new Error('Connection refused'))
        .mockResolvedValueOnce(mongoose);
      
      await connect();
      
      expect(connectSpy).toHaveBeenCalledTimes(3);
    });
  });
  
  describe('Indexes', () => {
    it('should create required indexes', async () => {
      await connect();
      const indexes = await mongoose.connection.db.collection('users').indexes();
      
      expect(indexes).toContainEqual(
        expect.objectContaining({ key: { email: 1 }, unique: true })
      );
    });
  });
});
```
