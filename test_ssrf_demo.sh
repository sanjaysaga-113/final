#!/bin/bash
# Quick SSRF Testing Script for Demo Vulnerable App
# Usage: bash test_ssrf_demo.sh

set -e

echo "=========================================="
echo "SSRF Module Testing on Demo Vulnerable App"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Start demo app
echo -e "${YELLOW}[*]${NC} Starting demo vulnerable app on port 8000..."
cd demo_vuln_app
python app.py --port 8000 > /tmp/demo_app.log 2>&1 &
DEMO_PID=$!
cd ..

# Wait for app to start
sleep 3

# Step 2: Verify app is running
echo -e "${YELLOW}[*]${NC} Verifying demo app is running..."
if curl -s "http://127.0.0.1:8000/" > /dev/null 2>&1; then
    echo -e "${GREEN}[+]${NC} Demo app started (PID: $DEMO_PID)"
else
    echo -e "${RED}[-]${NC} Failed to start demo app!"
    echo "Check logs: cat /tmp/demo_app.log"
    exit 1
fi

# Step 3: Test endpoint manually
echo -e "${YELLOW}[*]${NC} Testing /fetch_image endpoint manually..."
MANUAL_TEST=$(curl -s "http://127.0.0.1:8000/fetch_image?url=http://example.com/test.jpg" | jq -r '.status' 2>/dev/null)
if [ "$MANUAL_TEST" = "success" ]; then
    echo -e "${GREEN}[+]${NC} Endpoint is responsive"
else
    echo -e "${RED}[-]${NC} Endpoint test failed"
fi

# Step 4: Run SSRF scan
echo ""
echo -e "${YELLOW}[*]${NC} Running SSRF scan..."
echo "Command: python main.py --scan ssrf -f demo_vuln_app/urls_ssrf.txt --listener http://127.0.0.1:5000 --wait 30 --threads 2"
echo ""

python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2

SCAN_RESULT=$?

# Step 5: Check results
echo ""
echo -e "${YELLOW}[*]${NC} Checking results..."
echo ""

if [ -f "bssrf/output/findings_ssrf.json" ]; then
    echo -e "${GREEN}[+]${NC} Findings file created"
    echo ""
    echo "Results:"
    cat bssrf/output/findings_ssrf.json | jq . 2>/dev/null || cat bssrf/output/findings_ssrf.json
else
    echo -e "${RED}[-]${NC} No findings file found"
fi

# Step 6: Get callbacks
echo ""
echo -e "${YELLOW}[*]${NC} Callbacks received:"
curl -s http://127.0.0.1:5000/api/callbacks | jq . 2>/dev/null || echo "(No callbacks found)"

# Cleanup
echo ""
echo -e "${YELLOW}[*]${NC} Cleaning up..."
kill $DEMO_PID 2>/dev/null || true
sleep 1

if [ $SCAN_RESULT -eq 0 ]; then
    echo -e "${GREEN}[+]${NC} Test completed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Review findings: cat bssrf/output/findings_ssrf.json"
    echo "  2. Check callbacks: cat bssrf/output/callbacks.json"
else
    echo -e "${RED}[-]${NC} Scan encountered issues (exit code: $SCAN_RESULT)"
fi

echo ""
