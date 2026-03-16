"""
FastAPI Backend for AI Port Scan Risk Intelligence Engine

Three Clean API Views:
  1. POST /scan - Returns dashboard only (frontend safe, minimal)
  2. GET /report/{scan_id} - Returns detailed report (technical users, includes SHAP)
  3. GET /admin/status - Returns admin/operational metrics (backend only)

All SHAP, drift detection, and model internals hidden from frontend.
No print statements - structured JSON responses only.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os
import json
import uuid
from datetime import datetime
import tempfile

# Import the refactored analysis engine
from scripts.predict_risk import analyze_scan

# ============================================================================
# FASTAPI APP SETUP
# ============================================================================

app = FastAPI(
    title="AI Port Scan Risk Intelligence Engine",
    description="Production-ready port scan analysis with ML risk scoring",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# DATA MODELS
# ============================================================================

class DashboardResponse(BaseModel):
    """Frontend-safe minimal risk assessment"""
    host: str
    final_risk: str
    risk_score: float
    confidence: float
    security_score: int
    risk_tier: str
    open_ports: List[int]
    critical_port_count: int
    high_port_count: int
    total_ports: int
    active_services: List[str]
    operating_system: str
    recommendations: List[str]


class FeatureImportance(BaseModel):
    """SHAP feature importance"""
    feature: str
    shap_value: float
    impact: str  # "increases_risk" or "decreases_risk"


class PortDetail(BaseModel):
    """Detailed port vulnerability information"""
    port: int
    service: str
    risk_level: str
    cvss_score: str
    cve_examples: List[str]
    exploitability: str
    mitigation_priority: str


class ReportResponse(BaseModel):
    """Detailed technical report with SHAP explainability"""
    host: str
    operating_system: str
    active_services: List[str]
    ml_prediction: Dict[str, Any]
    hybrid_logic: Dict[str, Any]
    port_analysis: List[PortDetail]
    feature_analysis: Dict[str, Any]
    explainability: Dict[str, Any]
    security_score: Dict[str, Any]
    justification: str


class AdminResponse(BaseModel):
    """Backend operational metrics - NOT for frontend"""
    model_metadata: Dict[str, Any]
    training_info: Dict[str, Any]
    operational_metrics: Dict[str, Any]


class ScanResultResponse(BaseModel):
    """Unified response for dashboard endpoint"""
    scan_id: str
    timestamp: str
    dashboard: List[DashboardResponse]
    status: str
    message: str


class ReportResultResponse(BaseModel):
    """Unified response for report endpoint"""
    scan_id: str
    report: List[ReportResponse]
    status: str


# ============================================================================
# IN-MEMORY STORAGE (For demo - use database in production)
# ============================================================================

scan_cache: Dict[str, Dict] = {}


# ============================================================================
# HEALTH CHECK ENDPOINT
# ============================================================================

@app.get("/health", tags=["Health"])
async def health_check():
    """System health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "AI Port Scan Risk Intelligence Engine"
    }


# ============================================================================
# ENDPOINT 1: POST /scan - DASHBOARD ONLY (Frontend Safe)
# ============================================================================

@app.post("/scan", tags=["Scanning"], response_model=ScanResultResponse)
async def scan_ports(
    xml_file: UploadFile = File(..., description="Nmap XML output file"),
    return_report: bool = Query(False, description="Also return detailed report")
):
    """
    Scan Nmap XML output and return risk assessment.
    
    **Parameters:**
    - xml_file: Nmap XML scan file
    - return_report: Optional - also return full technical report
    
    **Returns:**
    - Dashboard view (always): Minimal, frontend-safe metrics
    - Report view (if return_report=true): Full technical analysis
    
    **Security:** No SHAP details or drift info in dashboard view.
    """
    
    try:
        # Generate scan ID
        scan_id = str(uuid.uuid4())[:8]
        
        # Save uploaded file temporarily (platform-independent)
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, f"nmap_scan_{scan_id}.xml")
        try:
            contents = await xml_file.read()
            with open(temp_file, "wb") as f:
                f.write(contents)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"File upload failed: {str(e)}")
        
        # Run analysis engine
        results = analyze_scan(temp_file)
        
        if results["error"]:
            raise HTTPException(status_code=400, detail=f"Analysis failed: {results['error']}")
        
        # Cache full results
        scan_cache[scan_id] = {
            "timestamp": datetime.now().isoformat(),
            "dashboard": results["dashboard"],
            "report": results["report"],
            "admin": results["admin"]
        }
        
        # Build response
        response_data = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "dashboard": results["dashboard"],
            "status": "success",
            "message": f"Scanned {len(results['dashboard'])} host(s)"
        }
        
        # Include report if requested
        if return_report:
            response_data["report"] = results["report"]
        
        # Clean up temp file
        try:
            os.remove(temp_file)
        except:
            pass
        
        return response_data
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


# ============================================================================
# ENDPOINT 2: GET /report/{scan_id} - DETAILED REPORT (Technical Users)
# ============================================================================

@app.get("/report/{scan_id}", tags=["Reporting"], response_model=ReportResultResponse)
async def get_detailed_report(
    scan_id: str = Path(..., description="Scan ID from /scan endpoint")
):
    """
    Get detailed technical report with SHAP explainability.
    
    **Path Parameters:**
    - scan_id: Unique scan identifier (from POST /scan)
    
    **Returns:**
    - Full report with SHAP feature importance
    - Port vulnerability details
    - ML prediction breakdown
    - Security scoring components
    
    **Access:** Technical/security teams only.
    """
    
    if scan_id not in scan_cache:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found. Run POST /scan first."
        )
    
    cached_data = scan_cache[scan_id]
    
    return {
        "scan_id": scan_id,
        "report": cached_data["report"],
        "status": "success"
    }


# ============================================================================
# ENDPOINT 3: GET /admin/status - ADMIN METRICS (Backend Only)
# ============================================================================

@app.get("/admin/status", tags=["Admin"], response_model=AdminResponse)
async def get_admin_status(
    api_key: str = Query(..., description="Admin API key for backend access")
):
    """
    Get admin/operational metrics (BACKEND ONLY - NOT FOR FRONTEND).
    
    **Query Parameters:**
    - api_key: Authentication key (set via environment variable ADMIN_API_KEY)
    
    **Returns:**
    - Model metadata (type, version, calibration)
    - Training information (samples, date, classes)
    - Operational metrics (processed samples, drift status)
    
    **Security:** Requires admin API key. Do NOT expose in frontend.
    """
    
    # Simple authentication (enhance in production)
    admin_key = os.getenv("ADMIN_API_KEY", "admin-secret-key-change-me")
    if api_key != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    
    # Get latest scan for metrics (if available)
    if scan_cache:
        latest_scan = list(scan_cache.values())[-1]
        admin_data = latest_scan.get("admin", {})
    else:
        admin_data = {
            "model_metadata": {
                "model_type": "XGBoost",
                "model_file": "model_*.pkl",
                "calibration_enabled": True,
                "feature_count": 9,
                "feature_names": [
                    "open_ports_count", "service_count", "avg_cvss",
                    "uncommon_ports", "os_flag", "port_severity_score",
                    "high_risk_port_count", "service_entropy", "cvss_variance"
                ]
            },
            "training_info": {
                "model_version": "1.0",
                "last_retrain_date": "2026-02-24",
                "training_samples": 1200,
                "model_classes": ["Low", "Medium", "High", "Critical"]
            },
            "operational_metrics": {
                "new_samples_processed": 0,
                "timestamp": datetime.now().isoformat(),
                "drift_status": "Not checked (run drift_detection.py separately)",
                "log_file": "data/new_scan_logs.csv"
            }
        }
    
    return admin_data


# ============================================================================
# AUXILIARY ENDPOINTS
# ============================================================================

@app.get("/scans", tags=["Utilities"])
async def list_scans():
    """List all cached scans with metadata"""
    scans_list = []
    for scan_id, data in scan_cache.items():
        scans_list.append({
            "scan_id": scan_id,
            "timestamp": data["timestamp"],
            "hosts_scanned": len(data["dashboard"]),
            "statuses": [h["final_risk"] for h in data["dashboard"]]
        })
    
    return {
        "total_scans": len(scans_list),
        "scans": scans_list
    }


@app.get("/scans/{scan_id}/summary", tags=["Utilities"])
async def get_scan_summary(scan_id: str):
    """Get summary statistics for a specific scan"""
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    data = scan_cache[scan_id]
    dashboard = data["dashboard"]
    
    # Calculate statistics
    critical_count = sum(1 for h in dashboard if h["final_risk"] == "Critical")
    high_count = sum(1 for h in dashboard if h["final_risk"] == "High")
    medium_count = sum(1 for h in dashboard if h["final_risk"] == "Medium")
    low_count = sum(1 for h in dashboard if h["final_risk"] == "Low")
    
    avg_security = sum(h["security_score"] for h in dashboard) / len(dashboard) if dashboard else 0
    total_ports = sum(h["total_ports"] for h in dashboard)
    
    return {
        "scan_id": scan_id,
        "timestamp": data["timestamp"],
        "hosts_scanned": len(dashboard),
        "risk_distribution": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        },
        "average_security_score": round(avg_security, 2),
        "total_open_ports": total_ports,
        "critical_ports_total": sum(h["critical_port_count"] for h in dashboard),
        "high_ports_total": sum(h["high_port_count"] for h in dashboard)
    }


@app.get("/api/docs", tags=["Documentation"])
async def api_documentation():
    """API documentation and usage guide"""
    return {
        "title": "AI Port Scan Risk Intelligence Engine",
        "version": "2.0.0",
        "endpoints": {
            "POST /scan": "Submit Nmap XML file for analysis",
            "GET /report/{scan_id}": "Get detailed technical report with SHAP",
            "GET /admin/status": "Get backend operational metrics (admin only)",
            "GET /health": "System health check",
            "GET /scans": "List all cached scans",
            "GET /scans/{scan_id}/summary": "Get scan summary statistics"
        },
        "views": {
            "dashboard": "Frontend-safe minimal metrics (no SHAP, no internals)",
            "report": "Full technical analysis for security teams",
            "admin": "Operational metrics for backend/infrastructure"
        },
        "ml_logic_preserved": True,
        "drift_detection": "Separate script (scripts/drift_detection.py)",
        "retraining": "Separate script (scripts/retrain_pipeline.py)"
    }


# ============================================================================
# ROOT ENDPOINT
# ============================================================================

@app.get("/", tags=["Root"])
async def root():
    """Welcome endpoint with API documentation links"""
    return {
        "message": "AI Port Scan Risk Intelligence Engine API",
        "version": "2.0.0",
        "documentation": "http://localhost:8000/docs",
        "alternative_docs": "http://localhost:8000/redoc",
        "endpoints": {
            "POST /scan": "Upload Nmap XML and get risk assessment",
            "GET /report/{scan_id}": "Get detailed technical report",
            "GET /admin/status": "Get operational metrics",
            "GET /docs": "Interactive API documentation",
            "GET /redoc": "Alternative documentation"
        }
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status": "failed"}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "status": "error"}
    )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
