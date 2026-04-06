import React, { createContext, useState, useCallback, useEffect } from "react";

export const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  // Check if token exists in localStorage on mount
  useEffect(() => {
    const storedToken = localStorage.getItem("auth-token");
    const storedUser = localStorage.getItem("auth-user");

    if (storedToken && storedUser) {
      try {
        setToken(storedToken);
        setUser(JSON.parse(storedUser));
        setIsAuthenticated(true);
      } catch (e) {
        console.error("Failed to restore auth from localStorage:", e);
        localStorage.removeItem("auth-token");
        localStorage.removeItem("auth-user");
      }
    }
    setLoading(false);
  }, []);

  const login = useCallback(async (email, password) => {
    try {
      const API_BASE = import.meta.env.VITE_MAIN_API_BASE || "http://127.0.0.1:8000";
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || "Login failed");
      }

      const data = await response.json();
      const newToken = data.access_token;
      const newUser = data.user;

      setToken(newToken);
      setUser(newUser);
      setIsAuthenticated(true);

      // Store in localStorage
      localStorage.setItem("auth-token", newToken);
      localStorage.setItem("auth-user", JSON.stringify(newUser));

      return { success: true };
    } catch (error) {
      console.error("Login error:", error);
      return { success: false, error: error.message };
    }
  }, []);

  const register = useCallback(async (name, email, password) => {
    try {
      const API_BASE = import.meta.env.VITE_MAIN_API_BASE || "http://127.0.0.1:8000";
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || "Registration failed");
      }

      const data = await response.json();
      return { success: true, message: data.message };
    } catch (error) {
      console.error("Registration error:", error);
      return { success: false, error: error.message };
    }
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
    localStorage.removeItem("auth-token");
    localStorage.removeItem("auth-user");
  }, []);

  const value = {
    isAuthenticated,
    user,
    token,
    loading,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
