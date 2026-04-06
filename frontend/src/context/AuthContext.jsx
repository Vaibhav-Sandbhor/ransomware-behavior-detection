import React, { createContext, useState, useCallback, useEffect, useRef } from "react";
import { startUserSession, endUserSession } from "../services/api.js";

export const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sessionId, setSessionId] = useState(null);

  // Ref to store the current dashboard state getter function (set by App.jsx)
  const getDashboardStateRef = useRef(null);
  // Ref to store the dashboard state reset function (set by App.jsx)
  const resetDashboardStateRef = useRef(null);

  // Check if token exists in localStorage on mount
  useEffect(() => {
    const storedToken = localStorage.getItem("auth-token");
    const storedUser = localStorage.getItem("auth-user");
    const storedSessionId = localStorage.getItem("session-id");

    if (storedToken && storedUser) {
      try {
        setToken(storedToken);
        setUser(JSON.parse(storedUser));
        setIsAuthenticated(true);
        if (storedSessionId) {
          setSessionId(parseInt(storedSessionId, 10));
        }
      } catch (e) {
        console.error("Failed to restore auth from localStorage:", e);
        localStorage.removeItem("auth-token");
        localStorage.removeItem("auth-user");
        localStorage.removeItem("session-id");
      }
    }
    setLoading(false);
  }, []);

  // Function to register the dashboard state getter
  const registerDashboardStateGetter = useCallback((getter) => {
    getDashboardStateRef.current = getter;
  }, []);

  // Function to register the dashboard state resetter
  const registerDashboardStateResetter = useCallback((resetter) => {
    resetDashboardStateRef.current = resetter;
  }, []);

  // Clear all cached dashboard data from localStorage
  const clearCachedDashboardData = useCallback(() => {
    // Clear any cached scan data (keep only auth-related keys)
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && !key.startsWith("auth-")) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));
    console.log("🧹 Cleared cached dashboard data from localStorage");
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

      // IMPORTANT: Clear cached data BEFORE setting auth state
      clearCachedDashboardData();

      setToken(newToken);
      setUser(newUser);
      setIsAuthenticated(true);

      // Store in localStorage
      localStorage.setItem("auth-token", newToken);
      localStorage.setItem("auth-user", JSON.stringify(newUser));

      // Start a new session after login
      try {
        const sessionData = await startUserSession();
        if (sessionData.session_id) {
          setSessionId(sessionData.session_id);
          localStorage.setItem("session-id", sessionData.session_id.toString());
          console.log(`✅ Session started: ${sessionData.session_id} (${sessionData.status})`);
        }
      } catch (sessionError) {
        console.error("Failed to start session:", sessionError);
      }

      return { success: true };
    } catch (error) {
      console.error("Login error:", error);
      return { success: false, error: error.message };
    }
  }, [clearCachedDashboardData]);

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

  const logout = useCallback(async () => {
    // Save final snapshot before logging out
    if (getDashboardStateRef.current && sessionId) {
      try {
        const dashboardState = getDashboardStateRef.current();
        if (dashboardState) {
          console.log("📸 Saving final snapshot before logout...");
          await endUserSession(dashboardState);
          console.log("✅ Final snapshot saved");
        }
      } catch (error) {
        console.error("Failed to save final snapshot:", error);
      }
    }

    // Reset dashboard state if resetter is registered
    if (resetDashboardStateRef.current) {
      resetDashboardStateRef.current();
    }

    // Clear ALL localStorage data (including cached dashboard data)
    clearCachedDashboardData();

    // Clear state
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
    setSessionId(null);
    localStorage.removeItem("auth-token");
    localStorage.removeItem("auth-user");
    localStorage.removeItem("session-id");
  }, [sessionId, clearCachedDashboardData]);

  const value = {
    isAuthenticated,
    user,
    token,
    loading,
    sessionId,
    login,
    register,
    logout,
    registerDashboardStateGetter,
    registerDashboardStateResetter,
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
