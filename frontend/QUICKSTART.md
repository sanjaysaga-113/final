# Quick Setup Guide
# Black-Box Web Vulnerability Scanner Frontend

## 1. Navigate to Frontend Directory
```bash
cd "/mnt/c/Users/YourUser/path/to/final year project/frontend"
# OR on Kali Linux directly:
cd ~/final\ year\ project/frontend
```

## 2. Install Dependencies
```bash
pip3 install -r requirements.txt
```

## 3. Start the Application

### Option A: Direct Python
```bash
python3 app.py
```

### Option B: Using Startup Script
```bash
chmod +x start.sh
./start.sh
```

### Option C: Production Mode (Gunicorn)
```bash
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
```

## 4. Access Dashboard
Open browser and go to:
```
http://localhost:5000
```

Or from another device on the same network:
```
http://<your-kali-ip>:5000
```

## 5. Test the Frontend (Without Backend Integration)

The frontend will work standalone but scans will fail because `main.py` needs to be updated.

### Minimal Test:
1. Select "Single URL"
2. Enter: `https://example.com/test?param=value`
3. Uncheck "Enable Reconnaissance"
4. Select at least one module (e.g., Blind XSS)
5. Click "Start Scan"

You'll see the terminal output attempting to launch the scanner.

## 6. Integrate with Your Backend

Edit your existing `main.py` to accept these arguments:

```python
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--url', help='Single target URL')
parser.add_argument('--file', help='File with target URLs')
parser.add_argument('--no-recon', action='store_true')
parser.add_argument('--recon-passive', action='store_true')
parser.add_argument('--recon-active', action='store_true')
parser.add_argument('--xss', action='store_true')
parser.add_argument('--sqli', action='store_true')
parser.add_argument('--ssrf', action='store_true')
parser.add_argument('--cmdi', action='store_true')
parser.add_argument('--xxe', action='store_true')

args = parser.parse_args()

# Your existing code, modified to use args
```

See `INTEGRATION_EXAMPLE.py` for a complete example.

## 7. Verify Real-Time Output

The terminal panel should show:
- WebSocket connection messages
- Scan initialization
- Module execution logs
- Real-time progress updates

## 8. Common Issues

### Port Already in Use
```bash
# Kill process on port 5000
sudo lsof -ti:5000 | xargs kill -9
```

### WebSocket Connection Failed
- Check Flask-SocketIO version: `pip show Flask-SocketIO`
- Try polling transport (edit app.js): `transports: ['polling']`

### Module Output Not Found
- Ensure your modules write to `*/output/findings*.json`
- Check file permissions on output directories

### Python Version
Requires Python 3.10+. Check with:
```bash
python3 --version
```

## 9. Development Tips

### Auto-reload on Code Changes
Flask debug mode is enabled by default in `app.py`:
```python
socketio.run(app, debug=True)
```

### View Browser Console
Press F12 in browser to see JavaScript logs and WebSocket messages.

### Test WebSocket Connection
In browser console:
```javascript
window.scannerApp.socket.connected  // Should be true
```

### Manual Log Entry
In browser console:
```javascript
window.scannerApp.logToTerminal('INFO', 'Test message')
```

## 10. Next Steps

- [ ] Update `main.py` with argument parsing
- [ ] Test with real scan modules
- [ ] Verify output file formats match expected structure
- [ ] Add authentication (if needed)
- [ ] Deploy to production server

## Support

For issues, check:
1. Terminal output in the web UI
2. Flask console logs
3. Browser developer console
4. `frontend/logs/` directory

---
**Ready to scan!** 🚀
