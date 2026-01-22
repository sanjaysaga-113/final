#!/bin/bash

# ============================================================================
# Flask Frontend Startup Script
# ============================================================================

echo "========================================"
echo "Black-Box Vulnerability Scanner Frontend"
echo "========================================"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "[INFO] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "[INFO] Activating virtual environment..."
source venv/bin/activate

# Install/update dependencies
echo "[INFO] Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo ""
echo "[SUCCESS] Setup complete!"
echo ""
echo "Starting Flask application on http://0.0.0.0:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo "========================================"
echo ""

# Start Flask application
python app.py
