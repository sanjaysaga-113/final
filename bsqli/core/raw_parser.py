import os
from urllib.parse import urlparse


def parse_raw_request(file_path: str):
    """
    Parse a raw HTTP request file (sqlmap -r style).
    Supports basic GET/POST with headers and optional body.
    Returns dict with method, url, headers, cookies, body, content_type.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)

    with open(file_path, "r", encoding="utf-8") as f:
        raw = f.read()

    # Split headers/body
    parts = raw.split("\n\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    header_lines = [line.strip("\r") for line in header_block.splitlines() if line.strip()]
    if not header_lines:
        raise ValueError("Invalid raw request: missing request line")

    request_line = header_lines[0]
    try:
        method, path, _ = request_line.split()
    except ValueError:
        raise ValueError("Invalid request line")

    headers = {}
    cookies = {}
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        name, val = line.split(":", 1)
        headers[name.strip()] = val.strip()

    # Build absolute URL from Host header + path
    host = headers.get("Host")
    if not host:
        raise ValueError("Host header is required in raw request")
    scheme = "https" if headers.get("X-Forwarded-Proto", "http").lower() == "https" else "http"
    url = f"{scheme}://{host}{path}"

    # Parse cookies
    if "Cookie" in headers:
        for pair in headers["Cookie"].split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    content_type = headers.get("Content-Type", "")

    return {
        "method": method.upper(),
        "url": url,
        "headers": headers,
        "cookies": cookies,
        "body": body,
        "content_type": content_type,
    }
