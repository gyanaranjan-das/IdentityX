# Auth UI Module

## Module Purpose

Implement secure, accessible authentication UI components including login, register, and password reset screens with client-side validation and proper error handling.

---

## Responsibilities

### MUST Do:
- Render authentication forms
- Validate input client-side (UX improvement only)
- Display server errors clearly
- Handle loading and disabled states
- Maintain accessibility standards

### MUST NOT Do:
- Make security decisions (server responsibility)
- Store passwords in state
- Trust client-side validation alone
- Expose sensitive error details

---

## Folder Structure

```
src/features/auth/
├── components/
│   ├── LoginForm.jsx
│   ├── RegisterForm.jsx
│   ├── PasswordResetForm.jsx
│   ├── PasswordResetConfirm.jsx
│   └── AuthLayout.jsx
├── hooks/
│   ├── useAuth.js
│   └── useAuthForm.js
├── pages/
│   ├── LoginPage.jsx
│   ├── RegisterPage.jsx
│   └── PasswordResetPage.jsx
├── validation/
│   └── authSchemas.js
└── index.js
```

---

## Data Structures

### 1. Form State (Finite State Machine)
```
States: IDLE → VALIDATING → SUBMITTING → SUCCESS | ERROR

┌─────────┐  submit   ┌────────────┐
│  IDLE   │ ────────> │ VALIDATING │
└─────────┘           └────────────┘
     ▲                      │
     │                      │ valid
     │ reset                ▼
     │               ┌────────────┐
     │               │ SUBMITTING │
     │               └────────────┘
     │                 /         \
     │           success        error
     │              /             \
     ▼             ▼               ▼
┌─────────┐   ┌─────────┐   ┌─────────┐
│ SUCCESS │   │ REDIRECT│   │  ERROR  │
└─────────┘   └─────────┘   └─────────┘
```

### 2. Validation Errors Map
```javascript
// O(1) field error lookup
const errors = {
  email: 'Invalid email format',
  password: 'Password must be at least 8 characters',
};

// Access: errors['email'] → O(1)
```

---

## Implementation

### LoginForm.jsx

```jsx
import { useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import { validateLoginForm } from '../validation/authSchemas';

export function LoginForm() {
  const { login, isLoading, error } = useAuth();
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    // Clear field error on change
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Client-side validation (UX only)
    const validationErrors = validateLoginForm(formData);
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }

    try {
      await login(formData);
      // Redirect handled by auth hook
    } catch (err) {
      // Server errors displayed via useAuth error state
    }
  };

  return (
    <form onSubmit={handleSubmit} noValidate>
      <div className="form-group">
        <label htmlFor="email">Email</label>
        <input
          type="email"
          id="email"
          name="email"
          value={formData.email}
          onChange={handleChange}
          disabled={isLoading}
          aria-invalid={!!errors.email}
          aria-describedby={errors.email ? 'email-error' : undefined}
          autoComplete="email"
          required
        />
        {errors.email && (
          <span id="email-error" className="error" role="alert">
            {errors.email}
          </span>
        )}
      </div>

      <div className="form-group">
        <label htmlFor="password">Password</label>
        <input
          type="password"
          id="password"
          name="password"
          value={formData.password}
          onChange={handleChange}
          disabled={isLoading}
          aria-invalid={!!errors.password}
          autoComplete="current-password"
          required
        />
        {errors.password && (
          <span className="error" role="alert">{errors.password}</span>
        )}
      </div>

      {error && (
        <div className="server-error" role="alert">
          {error}
        </div>
      )}

      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Signing in...' : 'Sign In'}
      </button>
    </form>
  );
}
```

### RegisterForm.jsx

```jsx
import { useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import { validateRegisterForm } from '../validation/authSchemas';
import { PasswordStrengthIndicator } from './PasswordStrengthIndicator';

export function RegisterForm() {
  const { register, isLoading, error } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    confirmPassword: '',
  });
  const [errors, setErrors] = useState({});

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    const validationErrors = validateRegisterForm(formData);
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }

    await register({
      email: formData.email,
      username: formData.username,
      password: formData.password,
    });
  };

  return (
    <form onSubmit={handleSubmit} noValidate>
      <div className="form-group">
        <label htmlFor="email">Email</label>
        <input
          type="email"
          id="email"
          name="email"
          value={formData.email}
          onChange={handleChange}
          disabled={isLoading}
          autoComplete="email"
        />
        {errors.email && <span className="error">{errors.email}</span>}
      </div>

      <div className="form-group">
        <label htmlFor="username">Username</label>
        <input
          type="text"
          id="username"
          name="username"
          value={formData.username}
          onChange={handleChange}
          disabled={isLoading}
          autoComplete="username"
        />
        {errors.username && <span className="error">{errors.username}</span>}
      </div>

      <div className="form-group">
        <label htmlFor="password">Password</label>
        <input
          type="password"
          id="password"
          name="password"
          value={formData.password}
          onChange={handleChange}
          disabled={isLoading}
          autoComplete="new-password"
        />
        <PasswordStrengthIndicator password={formData.password} />
        {errors.password && <span className="error">{errors.password}</span>}
      </div>

      <div className="form-group">
        <label htmlFor="confirmPassword">Confirm Password</label>
        <input
          type="password"
          id="confirmPassword"
          name="confirmPassword"
          value={formData.confirmPassword}
          onChange={handleChange}
          disabled={isLoading}
          autoComplete="new-password"
        />
        {errors.confirmPassword && (
          <span className="error">{errors.confirmPassword}</span>
        )}
      </div>

      {error && <div className="server-error">{error}</div>}

      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Creating account...' : 'Create Account'}
      </button>
    </form>
  );
}
```

### authSchemas.js (Client Validation)

```javascript
// Client-side validation (UX only - server is source of truth)

export function validateLoginForm({ email, password }) {
  const errors = {};
  
  if (!email) {
    errors.email = 'Email is required';
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.email = 'Invalid email format';
  }
  
  if (!password) {
    errors.password = 'Password is required';
  }
  
  return errors;
}

export function validateRegisterForm({ email, username, password, confirmPassword }) {
  const errors = {};
  
  // Email
  if (!email) {
    errors.email = 'Email is required';
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.email = 'Invalid email format';
  }
  
  // Username
  if (!username) {
    errors.username = 'Username is required';
  } else if (username.length < 3) {
    errors.username = 'Username must be at least 3 characters';
  } else if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    errors.username = 'Username can only contain letters, numbers, and underscores';
  }
  
  // Password strength
  if (!password) {
    errors.password = 'Password is required';
  } else {
    if (password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    } else if (!/[A-Z]/.test(password)) {
      errors.password = 'Password must contain an uppercase letter';
    } else if (!/[0-9]/.test(password)) {
      errors.password = 'Password must contain a number';
    }
  }
  
  // Confirm password
  if (password !== confirmPassword) {
    errors.confirmPassword = 'Passwords do not match';
  }
  
  return errors;
}

export function calculatePasswordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  
  if (score <= 2) return { level: 'weak', color: 'red' };
  if (score <= 4) return { level: 'medium', color: 'orange' };
  return { level: 'strong', color: 'green' };
}
```

---

## Security Considerations

1. **No password in state after submit** - Clear immediately
2. **HTTPS only** - Enforced at infrastructure level
3. **Client validation is UX only** - Server validates
4. **No sensitive data in error messages** - Generic messages
5. **Autocomplete attributes** - Browser password managers

---

## Accessibility

- Proper labels with `htmlFor`
- `aria-invalid` on error fields
- `aria-describedby` linking errors
- `role="alert"` for error messages
- Focus management on errors

---

## Testing

```javascript
describe('LoginForm', () => {
  it('should show validation errors', async () => {
    render(<LoginForm />);
    
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
    
    expect(await screen.findByText(/email is required/i)).toBeInTheDocument();
  });

  it('should call login on valid submit', async () => {
    const mockLogin = jest.fn();
    render(<LoginForm />, { authValue: { login: mockLogin } });
    
    fireEvent.change(screen.getByLabelIn('Email'), {
      target: { value: 'test@example.com' },
    });
    fireEvent.change(screen.getByLabelIn('Password'), {
      target: { value: 'password123' },
    });
    fireEvent.click(screen.getByRole('button'));
    
    expect(mockLogin).toHaveBeenCalledWith({
      email: 'test@example.com',
      password: 'password123',
    });
  });
});
```
