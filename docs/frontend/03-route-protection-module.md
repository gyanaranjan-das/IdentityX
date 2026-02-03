# Route Protection Module

## Module Purpose

Implement client-side route protection for authenticated and role-based access, with proper redirects and loading states.

---

## Responsibilities

### MUST Do:
- Guard protected routes from unauthenticated users
- Enforce role-based route access
- Handle redirect after login
- Show loading states during auth check
- Preserve intended destination

### MUST NOT Do:
- Replace server-side authorization
- Trust client-side alone for security
- Block public routes unnecessarily

---

## Folder Structure

```
src/routes/
├── ProtectedRoute.jsx
├── PublicRoute.jsx
├── RoleRoute.jsx
└── routeConfig.js
```

---

## Data Structures

### Route Configuration
```javascript
// Route definition with metadata
const routes = [
  { path: '/login', element: LoginPage, public: true, guestOnly: true },
  { path: '/register', element: RegisterPage, public: true, guestOnly: true },
  { path: '/dashboard', element: Dashboard, protected: true },
  { path: '/admin', element: AdminPanel, protected: true, roles: ['admin'] },
];
```

---

## Implementation

### ProtectedRoute.jsx

```jsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../features/auth/hooks/useAuth';

export function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  // Show loading while checking auth
  if (isLoading) {
    return (
      <div className="auth-loading">
        <span className="spinner" aria-label="Loading" />
      </div>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return (
      <Navigate 
        to="/login" 
        state={{ from: location.pathname }} 
        replace 
      />
    );
  }

  return children;
}
```

### PublicRoute.jsx

```jsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../features/auth/hooks/useAuth';

// For guest-only routes (login, register)
export function PublicRoute({ children, guestOnly = false }) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <div className="auth-loading"><span className="spinner" /></div>;
  }

  // Redirect authenticated users away from guest-only pages
  if (guestOnly && isAuthenticated) {
    const from = location.state?.from || '/dashboard';
    return <Navigate to={from} replace />;
  }

  return children;
}
```

### RoleRoute.jsx

```jsx
import { Navigate } from 'react-router-dom';
import { useAuth } from '../features/auth/hooks/useAuth';
import { ProtectedRoute } from './ProtectedRoute';

export function RoleRoute({ children, allowedRoles }) {
  const { user, isAuthenticated } = useAuth();

  // First check authentication
  return (
    <ProtectedRoute>
      <RoleCheck allowedRoles={allowedRoles}>
        {children}
      </RoleCheck>
    </ProtectedRoute>
  );
}

function RoleCheck({ children, allowedRoles }) {
  const { user } = useAuth();

  // Check role access
  if (!allowedRoles.includes(user?.role)) {
    return <Navigate to="/unauthorized" replace />;
  }

  return children;
}
```

### routeConfig.js

```javascript
import { lazy } from 'react';
import { ProtectedRoute } from './ProtectedRoute';
import { PublicRoute } from './PublicRoute';
import { RoleRoute } from './RoleRoute';

// Lazy load pages
const LoginPage = lazy(() => import('../pages/LoginPage'));
const RegisterPage = lazy(() => import('../pages/RegisterPage'));
const Dashboard = lazy(() => import('../pages/Dashboard'));
const Profile = lazy(() => import('../pages/Profile'));
const AdminPanel = lazy(() => import('../pages/AdminPanel'));
const Unauthorized = lazy(() => import('../pages/Unauthorized'));

export const routes = [
  // Public routes
  {
    path: '/login',
    element: (
      <PublicRoute guestOnly>
        <LoginPage />
      </PublicRoute>
    ),
  },
  {
    path: '/register',
    element: (
      <PublicRoute guestOnly>
        <RegisterPage />
      </PublicRoute>
    ),
  },
  
  // Protected routes
  {
    path: '/dashboard',
    element: (
      <ProtectedRoute>
        <Dashboard />
      </ProtectedRoute>
    ),
  },
  {
    path: '/profile',
    element: (
      <ProtectedRoute>
        <Profile />
      </ProtectedRoute>
    ),
  },
  
  // Role-protected routes
  {
    path: '/admin/*',
    element: (
      <RoleRoute allowedRoles={['admin', 'super_admin']}>
        <AdminPanel />
      </RoleRoute>
    ),
  },
  
  // Error pages
  {
    path: '/unauthorized',
    element: <Unauthorized />,
  },
];
```

### App.jsx Integration

```jsx
import { Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './features/auth/context/AuthContext';
import { routes } from './routes/routeConfig';

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Suspense fallback={<div className="page-loading">Loading...</div>}>
          <Routes>
            {routes.map(({ path, element }) => (
              <Route key={path} path={path} element={element} />
            ))}
            
            {/* Default redirect */}
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            
            {/* 404 */}
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </Suspense>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
```

---

## Role-Based UI Rendering

```jsx
import { useAuth } from '../features/auth/hooks/useAuth';

export function RoleBasedContent({ allowedRoles, children, fallback = null }) {
  const { user } = useAuth();
  
  if (!user || !allowedRoles.includes(user.role)) {
    return fallback;
  }
  
  return children;
}

// Usage
function Navigation() {
  return (
    <nav>
      <Link to="/dashboard">Dashboard</Link>
      <Link to="/profile">Profile</Link>
      
      <RoleBasedContent allowedRoles={['admin', 'super_admin']}>
        <Link to="/admin">Admin Panel</Link>
      </RoleBasedContent>
    </nav>
  );
}
```

---

## Security Note

Client-side route protection is for **UX only**. All sensitive data and actions MUST be protected by the backend API. Anyone can bypass client-side checks.

---

## Testing

```javascript
describe('ProtectedRoute', () => {
  it('should redirect unauthenticated users to login', () => {
    renderWithRouter(
      <AuthProvider initialState={{ isAuthenticated: false }}>
        <ProtectedRoute>
          <div>Protected Content</div>
        </ProtectedRoute>
      </AuthProvider>,
      { route: '/dashboard' }
    );
    
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    expect(window.location.pathname).toBe('/login');
  });

  it('should render protected content for authenticated users', () => {
    renderWithRouter(
      <AuthProvider initialState={{ isAuthenticated: true, user: mockUser }}>
        <ProtectedRoute>
          <div>Protected Content</div>
        </ProtectedRoute>
      </AuthProvider>
    );
    
    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });
});
```
