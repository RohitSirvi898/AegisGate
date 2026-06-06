import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import AuthScreen from './pages/AuthScreen';
import Dashboard from './components/Dashboard';

export default function App() {
  return (
    <AuthProvider>
      <HashRouter>
        <Routes>
          <Route path="/auth" element={<AuthScreen />} />
          <Route path="/dashboard" element={<Dashboard />} />
          {/* Default fallback route to navigate cleanly to secure paths */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </HashRouter>
    </AuthProvider>
  );
}
