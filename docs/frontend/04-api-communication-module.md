# API Communication Layer Module

## Module Purpose

Implement secure HTTP communication with the backend API, including automatic token refresh, request/response interceptors, and standardized error handling.

---

## Responsibilities

### MUST Do:
- Attach access token to authenticated requests
- Handle 401 responses with automatic token refresh
- Queue requests during token refresh
- Transform API errors to user-friendly messages
- Implement request/response logging

### MUST NOT Do:
- Store tokens in the API layer
- Retry indefinitely on failure
- Expose raw server errors to users
- Skip HTTPS in production

---

## Folder Structure

```
src/services/
├── api.js              # Axios instance configuration
├── authApi.js          # Auth-specific endpoints
├── userApi.js          # User-specific endpoints
└── interceptors/
    ├── auth.interceptor.js
    └── error.interceptor.js
```

---

## Data Structures

### Request Queue During Refresh
```
DSA: Queue (FIFO) for pending requests

When access token expires:
1. First 401 triggers refresh
2. Subsequent requests queued
3. After refresh, queue processed in order

┌─────────────────────────────────────────┐
│           Request Queue                 │
├─────────────────────────────────────────┤
│ [Request A] → [Request B] → [Request C] │
│     ↑                             ↑     │
│   HEAD                          TAIL    │
└─────────────────────────────────────────┘
```

---

## Implementation

### api.js

```javascript
import axios from 'axios';
import { tokenManager } from './tokenManager';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  withCredentials: true, // Send cookies (refresh token)
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - attach access token
api.interceptors.request.use(
  (config) => {
    const token = tokenManager.getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - handle errors and refresh
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) {
      reject(error);
    } else {
      resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 (Unauthorized)
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // Queue this request until refresh completes
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Attempt token refresh
        const response = await api.post('/v1/auth/refresh');
        const { accessToken } = response.data.data;
        
        tokenManager.setAccessToken(accessToken);
        processQueue(null, accessToken);
        
        originalRequest.headers.Authorization = `Bearer ${accessToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        tokenManager.clearAccessToken();
        
        // Redirect to login
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    // Transform error for UI
    return Promise.reject(transformError(error));
  }
);

function transformError(error) {
  if (!error.response) {
    return {
      code: 'NETWORK_ERROR',
      message: 'Unable to connect to server',
    };
  }

  const { data, status } = error.response;
  
  return {
    code: data?.error?.code || `HTTP_${status}`,
    message: data?.error?.message || 'An unexpected error occurred',
    details: data?.error?.details,
    status,
  };
}

export default api;
```

### authApi.js

```javascript
import api from './api';

export const authApi = {
  async login(credentials) {
    const response = await api.post('/v1/auth/login', credentials);
    return response.data.data;
  },

  async register(userData) {
    const response = await api.post('/v1/auth/register', userData);
    return response.data.data;
  },

  async refresh() {
    const response = await api.post('/v1/auth/refresh');
    return response.data.data;
  },

  async logout() {
    await api.post('/v1/auth/logout');
  },

  async requestPasswordReset(email) {
    const response = await api.post('/v1/auth/password-reset/request', { email });
    return response.data;
  },

  async confirmPasswordReset(token, password) {
    const response = await api.post('/v1/auth/password-reset/confirm', {
      token,
      password,
    });
    return response.data;
  },
};
```

### userApi.js

```javascript
import api from './api';

export const userApi = {
  async getProfile() {
    const response = await api.get('/v1/users/me');
    return response.data.data;
  },

  async updateProfile(data) {
    const response = await api.patch('/v1/users/me', data);
    return response.data.data;
  },

  async changePassword(currentPassword, newPassword) {
    const response = await api.patch('/v1/users/me/password', {
      currentPassword,
      newPassword,
    });
    return response.data;
  },
};
```

---

## Error Handling Hook

```javascript
import { useState, useCallback } from 'react';

export function useApiError() {
  const [error, setError] = useState(null);

  const handleError = useCallback((error) => {
    // Map error codes to user-friendly messages
    const messages = {
      INVALID_CREDENTIALS: 'Invalid email or password',
      EMAIL_EXISTS: 'This email is already registered',
      NETWORK_ERROR: 'Please check your internet connection',
      RATE_LIMIT_EXCEEDED: 'Too many attempts. Please try again later.',
      TOKEN_EXPIRED: 'Your session has expired. Please log in again.',
    };

    setError(messages[error.code] || error.message);
  }, []);

  const clearError = useCallback(() => setError(null), []);

  return { error, handleError, clearError };
}
```

---

## Security Considerations

1. **withCredentials: true** - Sends httpOnly cookies
2. **No token in URL** - Only in Authorization header
3. **Request queue** - Prevents race conditions during refresh
4. **Automatic logout on refresh failure** - Contains damage
5. **Error transformation** - No raw server errors exposed

---

## Testing

```javascript
describe('API Interceptors', () => {
  it('should attach authorization header', async () => {
    tokenManager.setAccessToken('test-token');
    
    mock.onGet('/test').reply(200, { data: 'success' });
    
    await api.get('/test');
    
    expect(mock.history.get[0].headers.Authorization).toBe('Bearer test-token');
  });

  it('should refresh token on 401', async () => {
    mock.onGet('/protected').replyOnce(401);
    mock.onPost('/v1/auth/refresh').reply(200, {
      data: { accessToken: 'new-token' },
    });
    mock.onGet('/protected').reply(200, { data: 'success' });
    
    const response = await api.get('/protected');
    
    expect(response.data.data).toBe('success');
    expect(tokenManager.getAccessToken()).toBe('new-token');
  });

  it('should queue requests during refresh', async () => {
    // ... test concurrent requests during refresh
  });
});
```
