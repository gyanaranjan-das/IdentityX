# Testing Strategy

## Overview

This document defines testing boundaries, strategies, and patterns for the authentication system.

---

## Testing Pyramid

```
          ┌─────────────┐
          │    E2E      │  Few, slow, high confidence
          │   Tests     │  
          ├─────────────┤
          │ Integration │  Moderate, test interactions
          │   Tests     │  
          ├─────────────┤
          │    Unit     │  Many, fast, isolated
          │   Tests     │  
          └─────────────┘
```

---

## Unit Test Boundaries

### Backend

| Module | What to Test | Mock Dependencies |
|--------|--------------|-------------------|
| user.model | Validation, virtuals, methods | None |
| user.service | Business logic | userRepository |
| auth.service | Auth flows | userService, tokenService |
| jwt.service | Token gen/validation | blacklistService |
| rateLimiter | Rate logic | Redis client |

### Frontend

| Module | What to Test | Mock |
|--------|--------------|------|
| LoginForm | Rendering, validation | useAuth hook |
| AuthContext | State transitions | authApi |
| ProtectedRoute | Redirect logic | useAuth |
| tokenManager | Token storage | None |

---

## Integration Test Boundaries

### Backend

| Flow | Components Tested | Setup |
|------|-------------------|-------|
| Registration | Controller → Service → Repository → DB | Test MongoDB |
| Login | Controller → Service → TokenService → DB | Test MongoDB |
| Token refresh | Controller → SessionService → DB | Seeded session |
| Rate limiting | Middleware → Redis | Test Redis |

### Frontend

| Flow | Components Tested | Setup |
|------|-------------------|-------|
| Login flow | Form → Context → API | MSW for API mocks |
| Token refresh | Interceptor → TokenManager | MSW |
| Protected routes | Router → Context integration | Test wrapper |

---

## Example Test Files

### Backend Unit Test

```javascript
// tests/unit/auth.service.test.js
describe('AuthService', () => {
  let authService;
  let mockUserRepository;
  let mockTokenService;

  beforeEach(() => {
    mockUserRepository = {
      findByEmail: jest.fn(),
      create: jest.fn(),
    };
    mockTokenService = {
      generatePair: jest.fn(),
    };
    authService = new AuthService(mockUserRepository, mockTokenService);
  });

  describe('login', () => {
    it('should return tokens on valid credentials', async () => {
      const mockUser = {
        id: '123',
        email: 'test@test.com',
        comparePassword: jest.fn().mockResolvedValue(true),
        isLocked: false,
      };
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockTokenService.generatePair.mockReturnValue({
        accessToken: 'access',
        refreshToken: 'refresh',
      });

      const result = await authService.login({
        email: 'test@test.com',
        password: 'password',
      });

      expect(result.tokens.accessToken).toBe('access');
    });

    it('should throw on invalid password', async () => {
      const mockUser = {
        comparePassword: jest.fn().mockResolvedValue(false),
        incrementLoginAttempts: jest.fn(),
      };
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);

      await expect(authService.login({
        email: 'test@test.com',
        password: 'wrong',
      })).rejects.toThrow('Invalid');
    });
  });
});
```

### Backend Integration Test

```javascript
// tests/integration/auth.integration.test.js
describe('Auth Integration', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.TEST_MONGODB_URI);
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    await User.deleteMany({});
  });

  describe('POST /api/v1/auth/register', () => {
    it('should create user and return tokens', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'test@example.com',
          username: 'testuser',
          password: 'SecurePass123!',
        });

      expect(res.status).toBe(201);
      expect(res.body.data.accessToken).toBeDefined();
      expect(res.headers['set-cookie']).toBeDefined();
    });
  });
});
```

### Frontend Unit Test

```javascript
// tests/unit/LoginForm.test.jsx
import { render, screen, fireEvent } from '@testing-library/react';
import { LoginForm } from '../LoginForm';
import { AuthProvider } from '../context/AuthContext';

describe('LoginForm', () => {
  it('shows validation error for empty email', async () => {
    render(
      <AuthProvider>
        <LoginForm />
      </AuthProvider>
    );

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByText(/email is required/i)).toBeInTheDocument();
  });
});
```

---

## Running Tests

### Backend

```bash
# Unit tests
npm run test:unit

# Integration tests (requires test DB)
npm run test:integration

# All tests with coverage
npm run test:coverage
```

### Frontend

```bash
# Unit tests
npm run test

# With coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

---

## Test Coverage Goals

| Type | Backend | Frontend |
|------|---------|----------|
| Unit | 80%+ | 70%+ |
| Integration | Key flows | Key flows |
| E2E | Critical paths | Critical paths |

---

## CI/CD Integration

```yaml
# .github/workflows/test.yml
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      mongodb:
        image: mongo:6
        ports:
          - 27017:27017
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: npm ci
      - name: Run backend tests
        run: npm run test:coverage
        working-directory: ./backend
      - name: Run frontend tests
        run: npm run test:coverage
        working-directory: ./frontend
```

---

## What NOT to Test

- Third-party library internals
- Framework behavior
- Pure configuration
- Generated code
