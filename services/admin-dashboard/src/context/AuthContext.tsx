import React, { createContext, useContext, useState } from 'react';

interface AuthContextType {
  token: string | null;
  activeProjectId: string | null;
  login: (token: string) => void;
  logout: () => void;
  setActiveProject: (projectId: string | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(localStorage.getItem('aegis_token'));
  const [activeProjectId, setActiveProjectIdState] = useState<string | null>(localStorage.getItem('aegis_active_project_id'));

  const login = (newToken: string) => {
    localStorage.setItem('aegis_token', newToken);
    setToken(newToken);
  };

  const logout = () => {
    localStorage.removeItem('aegis_token');
    localStorage.removeItem('aegis_active_project_id');
    setToken(null);
    setActiveProjectIdState(null);
  };

  const setActiveProject = (projectId: string | null) => {
    if (projectId) {
      localStorage.setItem('aegis_active_project_id', projectId);
    } else {
      localStorage.removeItem('aegis_active_project_id');
    }
    setActiveProjectIdState(projectId);
  };

  return (
    <AuthContext.Provider value={{ token, activeProjectId, login, logout, setActiveProject }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
