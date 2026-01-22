# Production Deployment Checklist
## Black-Box Web Vulnerability Scanner Frontend

### 🔧 Pre-Deployment

#### 1. Environment Setup
- [ ] Python 3.10+ installed
- [ ] Virtual environment created: `python3 -m venv venv`
- [ ] Dependencies installed: `pip install -r requirements.txt`
- [ ] Environment variables configured: Copy `.env.example` to `.env`

#### 2. Security Configuration
- [ ] Generate secure SECRET_KEY:
  ```python
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- [ ] Update SECRET_KEY in `.env`
- [ ] Set FLASK_ENV=production in `.env`
- [ ] Configure CORS_ORIGINS to specific domain (remove `*`)
- [ ] Review file upload size limits
- [ ] Enable HTTPS (if applicable)

#### 3. Backend Integration
- [ ] Update `main.py` with argument parsing
- [ ] Test scanner execution manually
- [ ] Verify module output directories exist
- [ ] Test JSON output format compatibility
- [ ] Ensure proper permissions on output directories

#### 4. File Permissions
```bash
chmod 755 frontend/
chmod 755 frontend/uploads/
chmod 755 frontend/logs/
chmod 644 frontend/*.py
chmod 755 frontend/start.sh
```

---

### 🚀 Deployment Options

#### Option A: Development Server (Testing Only)
```bash
cd frontend
python app.py
```
**Access:** http://localhost:5000

#### Option B: Gunicorn (Recommended)
```bash
cd frontend
source venv/bin/activate
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
```

#### Option C: Systemd Service (Production)

1. Create service file:
```bash
sudo nano /etc/systemd/system/scanner-frontend.service
```

2. Add configuration:
```ini
[Unit]
Description=Black-Box Scanner Frontend
After=network.target

[Service]
Type=notify
User=YOUR_USER
Group=YOUR_GROUP
WorkingDirectory=/home/saga/final year project/frontend
Environment="PATH=/home/saga/final year project/frontend/venv/bin"
ExecStart=/home/saga/final year project/frontend/venv/bin/gunicorn \
    --worker-class eventlet \
    -w 1 \
    --bind 0.0.0.0:5000 \
    app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

3. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable scanner-frontend
sudo systemctl start scanner-frontend
sudo systemctl status scanner-frontend
```

#### Option D: Docker (Optional)

1. Create `Dockerfile`:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]
```

2. Build and run:
```bash
docker build -t scanner-frontend .
docker run -d -p 5000:5000 --name scanner scanner-frontend
```

---

### 🌐 Reverse Proxy Setup (Optional)

#### Nginx Configuration

1. Install Nginx:
```bash
sudo apt update
sudo apt install nginx
```

2. Create site configuration:
```bash
sudo nano /etc/nginx/sites-available/scanner
```

3. Add configuration:
```nginx
server {
    listen 80;
    server_name scanner.yourdomain.com;  # Change this

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        
        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Standard headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

4. Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### SSL/TLS with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d scanner.yourdomain.com
```

---

### 🧪 Testing

#### Basic Functionality
```bash
# Test WebSocket connection
curl -i -N -H "Connection: Upgrade" \
     -H "Upgrade: websocket" \
     http://localhost:5000/socket.io/

# Test API endpoint
curl http://localhost:5000/api/scan/status
```

#### Frontend Access
- [ ] Open browser to http://localhost:5000
- [ ] Verify UI loads correctly
- [ ] Check browser console for errors
- [ ] Test WebSocket connection (should see "WebSocket connected")

#### Integration Test
- [ ] Submit a test scan (URL input)
- [ ] Verify terminal shows output
- [ ] Check scan completes
- [ ] Verify results display
- [ ] Test report download

---

### 📊 Monitoring

#### View Application Logs
```bash
# If using systemd:
sudo journalctl -u scanner-frontend -f

# If running manually:
tail -f frontend/logs/*.log
```

#### Check Process Status
```bash
# Systemd service:
sudo systemctl status scanner-frontend

# Manual process:
ps aux | grep gunicorn
```

#### Monitor Port
```bash
sudo lsof -i :5000
```

---

### 🔥 Firewall Configuration

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 5000/tcp
sudo ufw reload

# iptables
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
sudo iptables-save
```

---

### 🐛 Troubleshooting

#### Port Already in Use
```bash
# Find process using port 5000
sudo lsof -ti:5000

# Kill process
sudo kill -9 $(sudo lsof -ti:5000)
```

#### Permission Denied on uploads/logs
```bash
chmod 755 frontend/uploads frontend/logs
chown -R YOUR_USER:YOUR_GROUP frontend/
```

#### WebSocket Connection Failed
- Check firewall allows port 5000
- Verify Flask-SocketIO installed: `pip show Flask-SocketIO`
- Check browser console for error details
- Try polling transport (edit app.js)

#### Scanner Process Not Starting
- Verify `main.py` path is correct
- Check Python executable: `which python3`
- Test manually: `python3 ../main.py --help`
- Review permissions on scanner directories

#### Module Results Not Found
```bash
# Check output directories exist
ls -la ../bxss/output/
ls -la ../bsqli/output/

# Create if missing
mkdir -p ../bxss/output ../bsqli/output ../bssrf/output ../bcmdi/output ../bxe/output
```

---

### 📈 Performance Tuning

#### Gunicorn Workers
For CPU-bound tasks, increase workers:
```bash
gunicorn --worker-class eventlet -w 4 --bind 0.0.0.0:5000 app:app
```

#### Nginx Caching (Static Files)
Add to Nginx config:
```nginx
location /static/ {
    alias /path/to/frontend/static/;
    expires 30d;
    add_header Cache-Control "public, immutable";
}
```

---

### 🔒 Security Hardening

#### Production Settings
- [ ] DEBUG mode disabled (`FLASK_ENV=production`)
- [ ] Secure SECRET_KEY generated
- [ ] CORS restricted to specific origins
- [ ] HTTPS enabled
- [ ] File upload limits enforced

#### Optional Enhancements
- [ ] Rate limiting (Flask-Limiter)
- [ ] Authentication (Flask-Login or JWT)
- [ ] Input sanitization audit
- [ ] SQL injection prevention (use ORM if adding database)
- [ ] Regular dependency updates

---

### 📋 Maintenance

#### Regular Tasks
```bash
# Update dependencies
pip install --upgrade -r requirements.txt

# Clear old uploads (older than 7 days)
find uploads/ -type f -mtime +7 -delete

# Rotate logs
find logs/ -type f -mtime +30 -delete

# Backup configurations
tar -czf backup-$(date +%Y%m%d).tar.gz .env frontend/
```

#### Monitoring Checklist
- [ ] Check disk space (uploads/logs)
- [ ] Review application logs for errors
- [ ] Monitor CPU/memory usage
- [ ] Verify WebSocket connections
- [ ] Test scan functionality weekly

---

### ✅ Final Verification

Before going live:
- [ ] All environment variables configured
- [ ] Backend integration tested
- [ ] HTTPS configured (if production)
- [ ] Firewall rules applied
- [ ] Service auto-starts on boot
- [ ] Backups configured
- [ ] Monitoring in place
- [ ] Documentation updated

---

### 🚀 Launch Command

```bash
# Start the service
sudo systemctl start scanner-frontend

# Verify it's running
sudo systemctl status scanner-frontend

# Check logs
sudo journalctl -u scanner-frontend -f

# Test in browser
# Navigate to: http://your-server-ip:5000
```

---

### 📞 Support Resources

- **Application Logs:** `frontend/logs/`
- **System Logs:** `sudo journalctl -u scanner-frontend`
- **Browser Console:** Press F12 in browser
- **Process Status:** `ps aux | grep gunicorn`

---

**Deployment Status:** ⏸️ Ready for deployment  
**Review this checklist before launching!**
