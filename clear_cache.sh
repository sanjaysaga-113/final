#!/bin/bash
# Clear Python cache and restart test

echo "Clearing Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true

echo "Python cache cleared!"
echo ""
echo "Now run the test again:"
echo "./test_ssrf_demo.sh"
