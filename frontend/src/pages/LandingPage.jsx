import React from "react";
import { Link } from "react-router-dom";
import "../styles/landing.css";

function LandingPage() {
  return (
    <div className="landing-page">
      {/* Top Navbar */}
      <nav className="landing-nav">
        <div className="landing-nav-left">
          <span className="landing-logo">🛡️</span>
          <span className="landing-brand">CTIMAF</span>
        </div>
        <div className="landing-nav-right">
          <Link to="/login" className="nav-btn nav-btn-login">
            Login
          </Link>
          <Link to="/register" className="nav-btn nav-btn-register">
            Register
          </Link>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="landing-hero">
        <div className="hero-content">
          <h1 className="hero-title">CTIMAF</h1>
          <p className="hero-subtitle">
            Cyber Threat Intelligence Monitoring & Analysis Framework
          </p>
          <p className="hero-description">
            A comprehensive Security Operations Center (SOC) platform powered by 
            AI-driven threat detection, real-time monitoring, and advanced analytics.
          </p>

          <div className="hero-cta">
            <Link to="/login" className="cta-btn cta-primary">
              Get Started
            </Link>
            <Link to="/register" className="cta-btn cta-secondary">
              Create Account
            </Link>
          </div>
        </div>

        {/* Feature Cards */}
        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">🔒</div>
            <h3 className="feature-title">AI Ransomware Detection</h3>
            <p className="feature-desc">
              Machine learning-powered ransomware detection using behavioral analysis 
              and real-time process monitoring.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🌐</div>
            <h3 className="feature-title">Port Scan Monitoring</h3>
            <p className="feature-desc">
              Continuous network surveillance with CVSS-based risk scoring and 
              vulnerability prioritization.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🍯</div>
            <h3 className="feature-title">Honeypot System</h3>
            <p className="feature-desc">
              Decoy file monitoring to detect and analyze malicious file access 
              patterns and intrusion attempts.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="landing-footer">
        <p>© 2026 CTIMAF - Cyber Threat Intelligence Monitoring & Analysis Framework</p>
      </footer>
    </div>
  );
}

export default LandingPage;
