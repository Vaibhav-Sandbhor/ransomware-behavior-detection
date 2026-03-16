#!/usr/bin/env python3
"""
Test script to verify API predictions from predict_risk.py
"""
import requests
import json
import sys
from pathlib import Path

# API endpoint
API_URL = "http://localhost:8000"
NMAP_FILE = "nmap_scans/scan1.xml"

def test_api():
    """Test the API with a sample Nmap scan"""
    
    # Check if Nmap file exists
    if not Path(NMAP_FILE).exists():
        print(f"❌ Error: {NMAP_FILE} not found")
        sys.exit(1)
    
    print("🔍 Testing AI Port Scan Risk Intelligence Engine API")
    print("=" * 60)
    
    # Test 1: Root endpoint
    print("\n[1] Testing root endpoint...")
    try:
        resp = requests.get(f"{API_URL}/")
        if resp.status_code == 200:
            print("✅ Root endpoint working")
            data = resp.json()
            print(f"   API Version: {data['version']}")
            print(f"   Message: {data['message']}")
        else:
            print(f"❌ Root endpoint failed: {resp.status_code}")
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("   Make sure the API is running: python api.py")
        sys.exit(1)
    
    # Test 2: Upload Nmap scan and get predictions
    print("\n[2] Uploading Nmap scan and getting predictions...")
    try:
        with open(NMAP_FILE, "rb") as f:
            files = {"xml_file": f}
            resp = requests.post(f"{API_URL}/scan", files=files)
        
        if resp.status_code == 200:
            print("✅ Scan analysis successful!")
            results = resp.json()
            
            # Extract predictions
            print("\n📊 PREDICTED OUTPUTS FROM predict_risk.py:")
            print("-" * 60)
            
            if "dashboard" in results:
                scan_id = results.get("scan_id", "unknown")
                print(f"\nScan ID: {scan_id}")
                
                for i, host_result in enumerate(results["dashboard"], 1):
                    print(f"\n🎯 Host {i}: {host_result['host']}")
                    print(f"  Final Risk Prediction: {host_result['final_risk']}")
                    print(f"  Risk Score: {host_result['risk_score']:.2f}%")
                    print(f"  Confidence: {host_result['confidence']:.2f}%")
                    print(f"  Security Score: {host_result['security_score']}/100")
                    print(f"  Risk Tier: {host_result['risk_tier']}")
                    print(f"  Open Ports: {host_result['total_ports']}")
                    print(f"    - Critical: {host_result['critical_port_count']}")
                    print(f"    - High: {host_result['high_port_count']}")
                    print(f"  Operating System: {host_result['operating_system']}")
                    print(f"  Active Services: {', '.join(host_result['active_services'])}")
                    print(f"  Recommendations:")
                    for rec in host_result['recommendations']:
                        print(f"    • {rec}")
            
            # Show full JSON response
            print("\n\n📋 FULL API RESPONSE (JSON):")
            print("-" * 60)
            print(json.dumps(results, indent=2))
            
        else:
            print(f"❌ Scan upload failed: {resp.status_code}")
            print(resp.text)
    
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    
    # Test 3: Get detailed report (if we got a scan_id)
    if "scan_id" in results:
        scan_id = results["scan_id"]
        print(f"\n[3] Fetching detailed technical report for scan {scan_id}...")
        try:
            resp = requests.get(f"{API_URL}/report/{scan_id}")
            if resp.status_code == 200:
                print("✅ Detailed report retrieved!")
                report = resp.json()
                print(f"\n📈 DETAILED ML ANALYSIS:")
                print("-" * 60)
                print(json.dumps(report, indent=2)[:1000] + "\n... (truncated)")
            else:
                print(f"❌ Report retrieval failed: {resp.status_code}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("✅ API testing complete!")

if __name__ == "__main__":
    test_api()
