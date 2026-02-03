# State Management Module

## Module Purpose

Manage authentication state lifecycle including user session data, token storage strategy, and reactive state updates across the application.

---

## Responsibilities

### MUST Do:
- Store authentication state centrally
- Manage token storage securely
- Provide auth state to all components
- Handle state synchronization across tabs
- Clean up state on logout

### MUST NOT Do:
- Store access tokens in localStorage
- Store passwords in any form
- Expose tokens to vulnerable code
- Persist sensitive data unnecessarily

---

## Folder Structure

```
src/features/auth/
├── context/
│   └── AuthContext.jsx
├── hooks/
│   ├── useAuth.js
│   └── useAuthState.js
├── store/
│   └── authReducer.js
└── services/
    └── tokenManager.js
```

---

## Data Structures

### 1. Auth State (Immutable Object)
```javascript
const authState = {
  user: null | {
    id: string,
    email: string,
    username: string,
    role: string,
  },
  isAuthenticated: boolean,
  isLoading: boolean,
  error: null | string,
};
```

### 2. State Reducer (State Machine)
```
DSA: Finite State Machine

Actions:
- AUTH_START → isLoading: true
- AUTH_SUCCESS → user: payload, isAuthenticated: true
- AUTH_FAILURE → error: payload, isAuthenticated: false
- AUTH_LOGOUT → reset to initial state
- AUTH_REFRESH → update tokens silently
```

---

## Token Storage Strategy

### Security Comparison

| Storage | XSS Safe | CSRF Safe | Recommendation |
|---------|----------|-----------|----------------|
| localStorage | ❌ | ✅ | Never for tokens |
| sessionStorage | ❌ | ✅ | Single-tab only |
| Memory | ✅ | ✅ | Access token ✓ |
| httpOnly Cookie | ✅ | ❌ | Refresh token ✓ |

### Implementation

```javascript
// Access token: in-memory only
// Refresh token: httpOnly cookie (set by server)

class TokenManager {
  #accessToken = null;
  
  setAccessToken(token) {
    this.#accessToken = token;
  }
  
  getAccessToken() {
    return this.#accessToken;
  }
  
  clearAccessToken() {
    this.#accessToken = null;
  }
  
  // Refresh token is in httpOnly cookie - no JS access
}
```

---

## Implementation

### AuthContext.jsx

```jsx
import { createContext, useContext, useReducer, useEffect, useCallback } from 'react';
import { authReducer, initialState } from '../store/authReducer';
import { authApi } from '../services/authApi';
import { tokenManager } from '../services/tokenManager';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Initialize auth on mount
  useEffect(() => {
    const initAuth = async () => {
      dispatch({ type: 'AUTH_START' });
      
      try {
        // Try to refresh token on load (uses httpOnly cookie)
        const data = await authApi.refresh();
        tokenManager.setAccessToken(data.accessToken);
        dispatch({ type: 'AUTH_SUCCESS', payload: data.user });
      } catch {
        // Not authenticated
        dispatch({ type: 'AUTH_LOGOUT' });
      }
    };
    
    initAuth();
  }, []);

  const login = useCallback(async (credentials) => {
    dispatch({ type: 'AUTH_START' });
    
    try {
      const data = await authApi.login(credentials);
      tokenManager.setAccessToken(data.accessToken);
      dispatch({ type: 'AUTH_SUCCESS', payload: data.user });
      return data.user;
    } catch (error) {
      dispatch({ type: 'AUTH_FAILURE', payload: error.message });
      throw error;
    }
  }, []);

  const register = useCallback(async (userData) => {
    dispatch({ type: 'AUTH_START' });
    
    try {
      const data = await authApi.register(userData);
      tokenManager.setAccessToken(data.accessToken);
      dispatch({ type: 'AUTH_SUCCESS', payload: data.user });
      return data.user;
    } catch (error) {
      dispatch({ type: 'AUTH_FAILURE', payload: error.message });
      throw error;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      tokenManager.clearAccessToken();
      dispatch({ type: 'AUTH_LOGOUT' });
    }
  }, []);

  const value = {
    ...state,
    login,
    register,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
```

### authReducer.js

```javascript
export const initialState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
};

export function authReducer(state, action) {
  switch (action.type) {
    case 'AUTH_START':
      return {
        ...state,
        isLoading: true,
        error: null,
      };
    
    case 'AUTH_SUCCESS':
      return {
        ...state,
        user: action.payload,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };
    
    case 'AUTH_FAILURE':
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.payload,
      };
    
    case 'AUTH_LOGOUT':
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      };
    
    case 'AUTH_UPDATE_USER':
      return {
        ...state,
        user: { ...state.user, ...action.payload },
      };
    
    default:
      return state;
  }
}
```

### tokenManager.js

```javascript
/**
 * Token Manager
 * - Access token: stored in memory (private variable)
 * - Refresh token: httpOnly cookie (managed by server)
 */

class TokenManager {
  #accessToken = null;
  #tokenExpiresAt = null;
  
  setAccessToken(token, expiresIn = 900) {
    this.#accessToken = token;
    this.#tokenExpiresAt = Date.now() + (expiresIn * 1000);
  }
  
  getAccessToken() {
    if (!this.#accessToken) return null;
    
    // Check if token is about to expire (within 60 seconds)
    if (this.isTokenExpiringSoon()) {
      return null; // Force refresh
    }
    
    return this.#accessToken;
  }
  
  isTokenExpiringSoon() {
    if (!this.#tokenExpiresAt) return true;
    return Date.now() >= (this.#tokenExpiresAt - 60000);
  }
  
  clearAccessToken() {
    this.#accessToken = null;
    this.#tokenExpiresAt = null;
  }
  
  hasToken() {
    return !!this.#accessToken;
  }
}

// Singleton instance
export const tokenManager = new TokenManager();
```

---

## Tab Synchronization

```javascript
// Sync logout across tabs
useEffect(() => {
  const handleStorageChange = (e) => {
    if (e.key === 'logout') {
      // Another tab logged out
      tokenManager.clearAccessToken();
      dispatch({ type: 'AUTH_LOGOUT' });
    }
  };
  
  window.addEventListener('storage', handleStorageChange);
  return () => window.removeEventListener('storage', handleStorageChange);
}, []);

// Trigger sync on logout
const logout = async () => {
  await authApi.logout();
  localStorage.setItem('logout', Date.now().toString());
  tokenManager.clearAccessToken();
  dispatch({ type: 'AUTH_LOGOUT' });
};
```

---

## Security Considerations

1. **Access token in memory** - Not accessible to XSS in localStorage
2. **Private class fields** - `#accessToken` not enumerable
3. **Refresh via httpOnly cookie** - Not accessible to JavaScript
4. **Tab sync only signals** - No token in localStorage
5. **Proactive refresh** - Before expiration

---

## Testing

```javascript
describe('AuthContext', () => {
  it('should initialize as not authenticated', () => {
    const { result } = renderHook(() => useAuth(), {
      wrapper: AuthProvider,
    });
    
    expect(result.current.isAuthenticated).toBe(false);
  });

  it('should authenticate on login', async () => {
    const { result } = renderHook(() => useAuth(), {
      wrapper: AuthProvider,
    });
    
    await act(async () => {
      await result.current.login({ email: 'test@test.com', password: 'pass' });
    });
    
    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.user).toBeDefined();
  });
});
```
