import React, { createContext, useContext, useEffect, useState } from 'react';

export interface User {
  id?: string;
  email?: string;
  role?: string;
  name?: string;
}

interface AuthContextType {
  token: string | null;
  user: User | null;
  activeProjectId: string | null;
  isLoading: boolean;
  login: (token: string, user?: User | null, initialProjectId?: string | null) => void;
  logout: () => void;
  setActiveProject: (projectId: string | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => {
    try {
      return localStorage.getItem('aegis_token');
    } catch {
      return null;
    }
  });

  const [user, setUser] = useState<User | null>(() => {
    try {
      const saved = localStorage.getItem('aegis_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [activeProjectId, setActiveProjectIdState] = useState<string | null>(() => {
    try {
      return localStorage.getItem('aegis_active_project_id');
    } catch {
      return null;
    }
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  const login = (newToken: string, newUser?: User | null, initialProjectId?: string | null) => {
    try {
      localStorage.setItem('aegis_token', newToken);
      if (newUser) {
        localStorage.setItem('aegis_user', JSON.stringify(newUser));
      }
      if (initialProjectId) {
        localStorage.setItem('aegis_active_project_id', initialProjectId);
      }
    } catch (e) {
      console.warn('Failed to write auth to localStorage:', e);
    }

    setToken(newToken);
    if (newUser !== undefined) setUser(newUser);
    if (initialProjectId !== undefined && initialProjectId !== null) {
      setActiveProjectIdState(initialProjectId);
    }
  };

  const logout = () => {
    try {
      localStorage.removeItem('aegis_token');
      localStorage.removeItem('aegis_user');
      localStorage.removeItem('aegis_active_project_id');
      localStorage.removeItem('aegis_projects');
    } catch (e) {
      console.warn('Failed to clear auth from localStorage:', e);
    }
    setToken(null);
    setUser(null);
    setActiveProjectIdState(null);
  };

  const setActiveProject = (projectId: string | null) => {
    try {
      if (projectId) {
        localStorage.setItem('aegis_active_project_id', projectId);
      } else {
        localStorage.removeItem('aegis_active_project_id');
      }
    } catch (e) {
      console.warn('Failed to write activeProjectId to localStorage:', e);
    }
    setActiveProjectIdState(projectId);
  };

  return (
    <AuthContext.Provider
      value={{
        token,
        user,
        activeProjectId,
        isLoading,
        login,
        logout,
        setActiveProject
      }}
    >
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
