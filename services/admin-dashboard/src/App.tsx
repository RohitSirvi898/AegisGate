import { HashRouter, Navigate, Route, Routes } from 'react-router-dom';

import Dashboard from './components/Dashboard';
import { AuthProvider } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import AuthScreen from './pages/AuthScreen';

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <HashRouter>
          <Routes>
            <Route path="/auth" element={<AuthScreen />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </HashRouter>
      </ToastProvider>
    </AuthProvider>
  );
}
