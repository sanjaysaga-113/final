# Vulnerable Demo App (Local Only)

Purpose-built for demonstrating this scanner live. Do NOT expose publicly.

## What it provides
- `/search?name=...`: Intentionally vulnerable SQL query (string concatenation).
  - Also simulates time-based delays if payload contains `WAITFOR DELAY '00:00:N'` or `SLEEP(N)`.
- `/comment?text=...`: Stores unsanitized comments and reflects them.
  - Simulates a “blind XSS” admin visit by parsing the stored text for URLs like `http(s)://<host>/c/<UUID>` or `//<host>/c/<UUID>` and calls `http://<host>/x.js?id=<UUID>` to trigger the callback server.

## Quick start

1. Start the vulnerable app (new terminal):

```bash
python demo_vuln_app/app.py --port 8000
```

2. Start a BXSS scan with built-in callback server:

- Prepare example URLs file:

```bash
echo http://127.0.0.1:8000/comment?text=hello > demo_vuln_app/urls_bxss.txt
```

- Run the scanner (this starts the callback server on port 5000):

```bash
python main.py --recon -f demo_vuln_app/urls_bxss.txt --scan bxss --listener http://127.0.0.1:5000 --wait 10
```

- The scanner injects payloads into `text`, the app simulates an admin “view” and calls the listener. You should see callbacks and correlated findings in `bxss/output/`.

3. Run a BSQLi scan:

- Prepare example URLs file:

```bash
echo http://127.0.0.1:8000/search?name=test > demo_vuln_app/urls_sqli.txt
```

- Run the scanner:

```bash
python main.py --recon -f demo_vuln_app/urls_sqli.txt --scan sqli --threads 5
```

- Expect boolean-based detection (content length/similarity changes). Time-based may also trigger due to the delay simulation.

## Notes
- This app is intentionally vulnerable. Only run it locally.
- For BXSS, payloads commonly reference `.../c/<UUID>`; the app maps those to `/x.js?id=<UUID>` to align with the callback server.
- Requirements are already included in the project (Flask, requests).
