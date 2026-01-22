# Vulnerable Demo App (Local Only)

Purpose-built for demonstrating this scanner live. Do NOT expose publicly.

## What it provides

### SQL Injection (BSQLi)
- `/search?name=...`: Intentionally vulnerable SQL query (string concatenation).
  - Also simulates time-based delays if payload contains `WAITFOR DELAY '00:00:N'` or `SLEEP(N)`.

### Cross-Site Scripting (Blind XSS)
- `/comment?text=...`: Stores unsanitized comments and reflects them.
  - Simulates a "blind XSS" admin visit by parsing the stored text for URLs like `http(s)://<host>/c/<UUID>` or `//<host>/c/<UUID>` and calls `http://<host>/x.js?id=<UUID>` to trigger the callback server.

### Server-Side Request Forgery (SSRF)
- `/fetch_image?url=...`: Fetches an image from user-supplied URL (vulnerable to SSRF).
- `/webhook?callback=...`: Registers a webhook callback (vulnerable to SSRF).
- `/fetch_file?file=...`: Fetches a file from user-supplied URL (vulnerable to SSRF).

### Command Injection (Blind CMDi)
- `/ping?host=...`: Pings a host with user-supplied hostname (vulnerable to blind CMDi).
  - Simulates time-based delays if payload contains `sleep N`, `timeout /t N`, or `ping -n N`.
- `/dns?domain=...`: Performs DNS lookup on user-supplied domain (vulnerable to blind CMDi).
  - Simulates time-based delays if payload contains `sleep N`, `timeout /t N`, or `ping -n N`.
- `/process?cmd=...`: Processes a command parameter (vulnerable to blind CMDi).
  - Simulates time-based delays if payload contains `sleep N`, `timeout /t N`, or `ping -n N`.

## Quick start

### 1. Start the vulnerable app (new terminal):

```bash
python demo_vuln_app/app.py --port 8000
```

### 2. Test SQL Injection (BSQLi):

```bash
echo http://127.0.0.1:8000/search?name=test > demo_vuln_app/urls_sqli.txt
python main.py --recon -f demo_vuln_app/urls_sqli.txt --scan sqli --threads 5
```

Expect boolean-based detection (content length/similarity changes). Time-based may also trigger due to the delay simulation.

### 3. Test Blind XSS (BXSS):

```bash
echo http://127.0.0.1:8000/comment?text=hello > demo_vuln_app/urls_bxss.txt
python main.py --recon -f demo_vuln_app/urls_bxss.txt --scan bxss --listener http://127.0.0.1:5000 --wait 10
```

The scanner injects payloads into `text`, the app simulates an admin "view" and calls the listener. You should see callbacks and correlated findings in `bxss/output/`.

### 4. Test SSRF (BSSRF):

```bash
echo http://127.0.0.1:8000/fetch_image?url=http://example.com > demo_vuln_app/urls_ssrf.txt
python main.py --recon -f demo_vuln_app/urls_ssrf.txt --scan ssrf --threads 5
```

### 5. Test Command Injection (Blind CMDi):

```bash
cat demo_vuln_app/urls_cmdi.txt
# Or run directly:
python main.py --recon -f demo_vuln_app/urls_cmdi.txt --scan cmdi --threads 5
```

Expected findings for CMDi:
- `/ping?host=127.0.0.1` → Vulnerable parameter: `host`
- `/dns?domain=example.com` → Vulnerable parameter: `domain`
- `/process?cmd=ls` → Vulnerable parameter: `cmd`

Payloads that will trigger delays:
```
; sleep 3
; sleep 5
; sleep 7
&& sleep 3
|| sleep 3
| sleep 3
```

## Notes
- This app is intentionally vulnerable. Only run it locally.
- For BXSS, payloads commonly reference `.../c/<UUID>`; the app maps those to `/x.js?id=<UUID>` to align with the callback server.
- For CMDi, the app simulates command execution by detecting injected `sleep`, `timeout`, and `ping` commands and delaying responses accordingly.
- Requirements are already included in the project (Flask, requests).
