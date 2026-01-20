import argparse
from recon.recon_manager import gather_parameterized_urls
from bsqli.modules.blind_sqli.sqli_module import BlindSQLiModule
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import time
from datetime import datetime
from typing import Dict, Any
from bsqli.core.logger import get_logger
from bsqli.core.config import THREADS
from bsqli.core.config import OUTPUT_DIR
from colorama import Fore, Back, Style

logger = get_logger("main")

def print_header(text):
    """Print a colored header."""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Back.BLACK}{text.center(70)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

def print_success(text):
    """Print success message."""
    print(f"{Fore.GREEN}[SUCCESS] {text}{Style.RESET_ALL}")

def print_error(text):
    """Print error message."""
    print(f"{Fore.RED}[ERROR] {text}{Style.RESET_ALL}")

def print_info(text):
    """Print info message."""
    print(f"{Fore.BLUE}[INFO] {text}{Style.RESET_ALL}")

def format_payload_snippet(payload: str, length: int = 80) -> str:
    """Return a colored payload snippet for terminal emphasis."""
    if not payload:
        return ""
    snippet = (payload or "")[:length]
    return f"{Back.YELLOW}{Fore.BLACK}{snippet}{Style.RESET_ALL}"

def write_outputs(findings, out_dir=OUTPUT_DIR):
    json_path = os.path.join(out_dir, "findings.json")
    txt_path = os.path.join(out_dir, "findings.txt")
    with open(json_path, "w") as f:
        json.dump(findings, f, indent=2)

    # Human-readable summary
    with open(txt_path, "w") as f:
        f.write("=" * 80 + "\n")
        f.write("SCAN FINDINGS\n")
        f.write("=" * 80 + "\n\n")
        if not findings:
            f.write("No confirmed findings.\n")
        for item in findings:
            inj_type = item.get("injection")
            param = item.get("parameter")
            url = item.get("url")
            details = item.get("details", {})
            conf = details.get("confidence", "UNKNOWN") if isinstance(details, dict) else "UNKNOWN"

            f.write(f"[+] {inj_type.upper()} on {param} ({url})\n")
            f.write(f"    Confidence: {conf}\n")

            # Boolean evidence summary
            if inj_type.startswith("boolean") and isinstance(details, dict):
                ev = details.get("evidence", [])
                f.write(f"    Evidence count: {len(ev)}\n")
                for i, e in enumerate(ev[:3], 1):
                    lt, lf = e.get("len_true"), e.get("len_false")
                    sim = e.get("sim")
                    f.write(f"      #{i}: len_true={lt}, len_false={lf}, sim={sim}\n")

            # Time evidence summary
            if inj_type.startswith("time") and isinstance(details, dict):
                ev = details.get("evidence", [])
                f.write(f"    Evidence count: {len(ev)}\n")
                for i, e in enumerate(ev[:3], 1):
                    base = e.get("baseline")
                    inj = e.get("t_inj")
                    f.write(f"      #{i}: baseline={base}s, injected={inj}s\n")

            f.write("-" * 80 + "\n")

    logger.info("Wrote results to %s and %s", json_path, txt_path)

def main():
    ap = argparse.ArgumentParser(
        description="B-SQLi - Blind SQL Injection & XSS Detection Framework",
        epilog="""
EXAMPLES:
  # SQLi scan with full URL (no recon needed)
  python main.py -u 'https://example.com/search?q=test' --scan sqli --threads 5
  
  # SQLi scan with recon to discover URLs from domain
  python main.py -u example.com --recon --recon-mode passive --scan sqli
  
  # SQLi scan from URL file (direct, no recon)
  python main.py -f targets.txt --scan sqli --threads 10
  
  # SQLi scan from URL file with recon (gau+gf filtering)
  python main.py -f targets.txt --recon --recon-mode passive --scan sqli
  
  # Blind XSS scan with active recon
  python main.py -u example.com --recon --recon-mode active --scan bxss --listener https://abc123.ngrok.io
  
  # Blind SSRF scan (no recon, direct targets)
  python main.py -f ssrf_targets.txt --scan ssrf --listener http://attacker.com:5000
  
  # Raw HTTP request (sqlmap style)
  python main.py --raw request.txt --scan sqli
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    ap.add_argument(
        "-u", "--url",
        help="Target domain/URL to scan (e.g., example.com or http://example.com/search?q=test)",
        required=False
    )
    ap.add_argument(
        "-f", "--file", "--urls",
        help="File containing one URL per line for batch scanning",
        required=False,
        dest="file"
    )
    ap.add_argument(
        "--recon",
        action="store_true",
        help="Enable reconnaissance: discover URLs with gau, filter with gf patterns, score by parameter risk"
    )
    ap.add_argument(
        "--recon-mode",
        choices=["passive", "active", "both"],
        default="passive",
        help="Recon mode: 'passive' (gau+gf only), 'active' (passive + blind recon), 'both' (alias for active). Only used with --recon"
    )
    ap.add_argument(
        "--scan",
        choices=["sqli", "bxss", "ssrf"],
        help="Scan module: 'sqli' for Blind SQL Injection, 'bxss' for Blind XSS, 'ssrf' for Blind SSRF",
        required=False
    )
    ap.add_argument(
        "--threads",
        type=int,
        default=THREADS,
        help=f"Number of concurrent threads for scanning (default: {THREADS}). Higher = faster but more aggressive"
    )
    ap.add_argument(
        "--listener",
        help="Callback/OOB server URL for BXSS detection. Use ngrok, Interactsh, or your own server (e.g., https://abc123.ngrok.io or http://attacker.com:5000)",
        required=False
    )
    ap.add_argument(
        "--wait",
        type=int,
        default=30,
        help="Wait time in seconds for BXSS callbacks after injection (default: 30). Higher = more time for callbacks, slower scanning"
    )
    ap.add_argument(
        "--raw",
        help="Raw HTTP request file (sqlmap -r format). Bypasses recon and scans the request directly. File format: raw HTTP with blank line before body",
        required=False
    )
    args = ap.parse_args()

    # Raw mode bypasses recon and accepts a sqlmap -r style request
    if args.raw:
        if args.scan and args.scan != "sqli":
            print_error("Raw mode currently supports only SQLi scanning.")
            return
        try:
            from bsqli.core.raw_parser import parse_raw_request
            raw_req = parse_raw_request(args.raw)
        except Exception as e:
            print_error(f"Failed to parse raw request: {e}")
            return

        print_header("RAW SQLI SCAN MODE")
        print_info(f"Target: {raw_req.get('url')} | Method: {raw_req.get('method')}")
        module = BlindSQLiModule(timeout=10)
        findings = module.scan_raw_request(raw_req)
        write_outputs(findings)
        logger.info("Raw scan complete. Total findings: %d", len(findings))
        return

    if not args.url and not args.file and not args.raw:
        print_error("Missing target! Provide either:")
        print("  -u URL/DOMAIN      for single target (with or without --recon)")
        print("  -f FILE            for batch scanning from file")
        print("  --raw FILE         for raw HTTP request")
        print("\nRun: python main.py -h for examples")
        return
    
    # BXSS and SSRF require listener URL
    if args.scan in ["bxss", "ssrf"] and not args.listener:
        print_error(f"{args.scan.upper()} scan requires --listener URL")
        print("Examples:")
        print("  --listener https://abc123.ngrok.io     (use ngrok)")
        print("  --listener https://interactsh.com      (Interactsh)")
        print("  --listener http://your-server:5000     (your own server)")
        return

    from_file = bool(args.file)
    scan_type = args.scan if args.scan else "sqli"
    
    # ========================================================================
    # PART A: DETERMINE TARGET HANDLING MODE
    # ========================================================================
    
    if from_file:
        # File input: URLs may or may not need recon depending on --recon flag
        if args.recon:
            print_info(f"[RECON] Enabled with mode: {args.recon_mode}")
            src = args.file
            urls = gather_parameterized_urls(src, from_file=True, scan_type=scan_type)
        else:
            # Direct mode: read URLs as-is from file
            print_info("[*] Recon disabled — using URLs directly from file")
            try:
                with open(args.file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print_info(f"Loaded {len(urls)} URLs from {args.file}")
            except Exception as e:
                print_error(f"Failed to read file {args.file}: {e}")
                return
    else:
        # Single URL input: check if it's a full URL with parameters or base domain
        url = args.url
        is_full_url_with_params = "?" in url and "=" in url
        
        if is_full_url_with_params and not args.recon:
            # Full URL with parameters, no recon requested
            print_info("[*] Recon disabled — using user-supplied target")
            urls = [url]
        elif args.recon:
            # Recon explicitly enabled
            print_info(f"[RECON] Enabled with mode: {args.recon_mode}")
            urls = gather_parameterized_urls(url, from_file=False, scan_type=scan_type)
        else:
            # Base domain without recon
            print_error("Base domain provided without --recon flag. Provide either:")
            print("  -u 'https://example.com/search?q=test'  (full URL, direct scan)")
            print("  -u 'example.com' --recon               (base domain, discover URLs)")
            return
    if not urls:
        print_error("No parameterized URLs found.")
        return

    findings = []
    
    # Route to appropriate module
    if args.scan == "bxss":
        print_header("BLIND XSS SCAN MODE")
        print_info(f"Listener URL: {args.listener}")
        if args.recon:
            print_info(f"[RECON] Mode: {args.recon_mode} | URLs discovered: {len(urls)}")
        else:
            print_info(f"[*] Recon disabled | Target URLs: {len(urls)}")
        
        # Import BXSS module
        from bxss.modules.blind_xss.xss_module import BlindXSSModule
        from bxss.oob.callback_server import start_server_background, get_callbacks
        from bxss.oob.correlation import correlate_callbacks, calculate_confidence, save_findings
        
        # Start callback server in background
        print_info("Starting OOB callback server...")
        server_thread = start_server_background(host='0.0.0.0', port=int(args.listener.split(':')[-1]))
        time.sleep(2)  # Give server time to start
        print_success("Callback server started")
        
        # Scan with BXSS module
        print_info(f"Starting BXSS scan with {args.threads} threads...")
        module = BlindXSSModule(listener_url=args.listener, timeout=10, wait_time=5)
        
        all_injections = []
        with ThreadPoolExecutor(max_workers=args.threads) as exe:
            futures = {exe.submit(module.scan_url, u): u for u in urls}
            for fut in as_completed(futures):
                try:
                    injections = fut.result()
                    if injections:
                        all_injections.extend(injections)
                        print(f"{Fore.MAGENTA}[INJECTION] {futures[fut]}: {len(injections)} payloads{Style.RESET_ALL}")
                except Exception as e:
                    logger.debug(f"Scan task error: {e}")
        
        print_success(f"Scan complete: {len(all_injections)} total injections")
        
        # Wait for delayed callbacks
        print_info(f"Waiting {args.wait}s for callbacks...")
        time.sleep(args.wait)
        
        # Correlate callbacks with injections
        callbacks = get_callbacks()
        print_info(f"Callbacks received: {len(callbacks)}")
        
        findings = correlate_callbacks(callbacks)
        confidence = calculate_confidence(findings)
        
        if findings:
            print_success(f"Found {len(findings)} XSS vulnerabilities (Confidence: {confidence}%)")
            # Human-friendly console summary
            for idx, fnd in enumerate(findings, 1):
                delay = fnd.get("delay_seconds")
                try:
                    delay_str = f"{float(delay):.2f}s" if delay is not None else "n/a"
                except Exception:
                    delay_str = "n/a"
                param = fnd.get("parameter")
                ml_conf = fnd.get("ml_confidence", "N/A")
                payload_snip = format_payload_snippet(fnd.get("payload", ""))
                print_info(
                    f"[{idx}] Target: {param} | Delay: {delay_str} | ML: {ml_conf} | Payload: {payload_snip}"
                )
        else:
            print_info("No callbacks correlated (may indicate stored XSS or network issues)")
        
        # Save findings
        if findings:
            json_file, txt_file = save_findings(findings, os.path.join("bxss", "output"))
            print_success(f"Results saved to {json_file}")

        else:
            logger.info("No BXSS vulnerabilities confirmed via callback.")
    elif args.scan == "ssrf" or args.scan == "bssrf":
        print_header("BLIND SSRF SCAN MODE")
        print_info(f"Listener URL: {args.listener}")
        if args.recon:
            print_info(f"[RECON] Mode: {args.recon_mode} | URLs discovered: {len(urls)}")
        else:
            print_info(f"[*] Recon disabled | Target URLs: {len(urls)}")
        
        # Import SSRF module
        from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
        from bssrf.oob.callback_server import start_server_background
        
        # Extract port from listener URL
        try:
            listener_port = int(args.listener.split(':')[-1])
        except (ValueError, IndexError):
            listener_port = 5000
        
        # Start callback server in background
        print_info("Starting OOB callback server...")
        server_thread = start_server_background(host='0.0.0.0', port=listener_port)
        time.sleep(2)  # Give server time to start
        print_success("Callback server started")
        
        # Initialize SSRF module
        print_info("Initializing SSRF detector...")
        module = BlindSSRFModule(listener_url=args.listener, timeout=10, wait_time=5)
        
        all_findings = []
        print_info(f"Starting SSRF scan with {args.threads} threads...")
        
        with ThreadPoolExecutor(max_workers=args.threads) as exe:
            futures = {exe.submit(module.scan_url, u): u for u in urls}
            for fut in as_completed(futures):
                try:
                    findings_list = fut.result()
                    if findings_list:
                        all_findings.extend(findings_list)
                        print(f"{Fore.MAGENTA}[SSRF] {futures[fut]}: {len(findings_list)} injection points{Style.RESET_ALL}")
                except Exception as e:
                    logger.debug(f"Scan task error: {e}")
        
        print_success(f"Scan complete: {len(all_findings)} total SSRF injection points")
        
        # Wait for delayed callbacks
        print_info(f"Waiting {args.wait}s for OOB callbacks...")
        module.wait_for_callbacks(timeout=args.wait)
        
        # Check which injections got callbacks (confirm vulnerabilities)
        print_info("Checking callback correlations...")
        confirmed_findings = []
        for finding in all_findings:
            uuid = finding.get('uuid')
            payload_type = finding.get('payload_type', '')
            status_code = finding.get('status_code', 0)
            
            # Only confirm if:
            # 1. We got a callback for this UUID, OR
            # 2. It's an HTTP payload to our listener with 200 status
            callback_received = uuid and module.check_callback_received(uuid)
            http_success = payload_type == 'http' and status_code == 200
            
            if callback_received or http_success:
                finding['confirmed'] = True
                finding['vulnerability_status'] = 'CONFIRMED'
                finding['confirmation_reason'] = 'Callback received' if callback_received else 'HTTP request successful'
                confirmed_findings.append(finding)
            else:
                finding['confirmed'] = False
                finding['vulnerability_status'] = 'POTENTIAL'
                finding['confirmation_reason'] = f'No callback (status: {status_code})'
        
        # Display results with clear status
        if all_findings:
            print_success(f"Scan Results: {len(all_findings)} injection points tested")
            print_success(f"Confirmed Vulnerabilities: {len(confirmed_findings)}")
            
            # Explanation
            print(f"\n{Fore.CYAN}{'='*80}")
            print(f"NOTE: SSRF is confirmed when the target makes an outbound request to our server.")
            print(f"Status codes (400, 504, etc) are from the TARGET, not our callback server.")
            print(f"What matters: Did our callback server receive the request? (confirmation)")
            print(f"{'='*80}{Style.RESET_ALL}\n")
            
            # Display confirmed vulnerabilities first
            if confirmed_findings:
                print(f"\n{Fore.GREEN}{'='*80}")
                print(f"CONFIRMED VULNERABLE ENDPOINTS (Callbacks Received)")
                print(f"{'='*80}{Style.RESET_ALL}\n")
                
                confirmed_by_url = {}
                for finding in confirmed_findings:
                    url = finding['url']
                    if url not in confirmed_by_url:
                        confirmed_by_url[url] = []
                    confirmed_by_url[url].append(finding)
                
                for url, findings_list in confirmed_by_url.items():
                    param = findings_list[0]['parameter']
                    print(f"{Fore.GREEN}✓ VULNERABLE:{Style.RESET_ALL} {url}")
                    print(f"  Parameter: {Fore.YELLOW}{param}{Style.RESET_ALL}")
                    print(f"  Confirmed via: {len(findings_list)} callback(s)")
                    
                    # Show confirmation details
                    confirmation_methods = set(f.get('confirmation_reason', 'Unknown') for f in findings_list)
                    print(f"  Confirmation: {', '.join(confirmation_methods)}")
                    
                    print(f"  Confidence: {Fore.GREEN}100%{Style.RESET_ALL}")
                    payload_types = set(f['payload_type'] for f in findings_list)
                    print(f"  Payload types: {', '.join(payload_types)}")
                    
                    # Show successful payloads
                    successful = [f for f in findings_list if f.get('status_code') == 200]
                    if successful:
                        print(f"  Successful requests: {len(successful)}/{len(findings_list)}")
                    print()
            
            # Display potential (unconfirmed) vulnerabilities
            unconfirmed = [f for f in all_findings if not f.get('confirmed')]
            if unconfirmed:
                print(f"\n{Fore.YELLOW}{'='*80}")
                print(f"POTENTIAL SSRF (No Callback Received - May be Filtered/Blocked)")
                print(f"{'='*80}{Style.RESET_ALL}\n")
                
                unconfirmed_by_url = {}
                for finding in unconfirmed:
                    url = finding['url']
                    if url not in unconfirmed_by_url:
                        unconfirmed_by_url[url] = []
                    unconfirmed_by_url[url].append(finding)
                
                for url, findings_list in unconfirmed_by_url.items():
                    param = findings_list[0]['parameter']
                    print(f"{Fore.YELLOW}? POTENTIAL:{Style.RESET_ALL} {url}")
                    print(f"  Parameter: {Fore.YELLOW}{param}{Style.RESET_ALL}")
                    print(f"  Status: Injection attempted but no callback received")
                    print(f"  Confidence: {Fore.YELLOW}Low{Style.RESET_ALL} (possible WAF/filter blocking)")
                    print()
        else:
            print_info("No SSRF-vulnerable parameters found in the scanned URLs.")
        
        # Save findings to output
        import json
        os.makedirs(os.path.join("bssrf", "output"), exist_ok=True)
        json_path = os.path.join("bssrf", "output", "findings_ssrf.json")
        txt_path = os.path.join("bssrf", "output", "findings_ssrf.txt")
        
        with open(json_path, "w") as f:
            json.dump(all_findings, f, indent=2)
        
        with open(txt_path, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("BLIND SSRF DETECTION FINDINGS\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total injection points found: {len(all_findings)}\n")
            f.write(f"Scan timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Callback Server: {args.listener}\n\n")
            
            if all_findings:
                for idx, finding in enumerate(all_findings, 1):
                    f.write(f"\n[FINDING #{idx}]\n")
                    f.write(f"URL: {finding.get('url')}\n")
                    f.write(f"Parameter: {finding.get('parameter')}\n")
                    f.write(f"Payload Type: {finding.get('payload_type')}\n")
                    f.write(f"Status Code: {finding.get('status_code')}\n")
                    f.write(f"Response Length: {finding.get('response_length')} bytes\n")
                    f.write(f"UUID (Callback ID): {finding.get('uuid')}\n")
                    f.write(f"Timestamp: {finding.get('timestamp')}\n")
                    f.write(f"Payload: {finding.get('payload')}\n")
                    f.write("-" * 80 + "\n")
            
            f.write("\n\nNOTE: Findings are CONFIRMED only when OOB callbacks are received.\n")
            f.write("Cross-reference UUIDs with callback server logs for confirmation.\n")
            f.write(f"Callback server running on: {args.listener}\n")
        
        print_success(f"Results saved to {json_path} and {txt_path}")
        print_info(f"Callback server running on {args.listener}")
        logger.info("SSRF scan complete. Total injection points: %d", len(all_findings))

    else:  # sqli (default)
        logger.info("================================================================================")
        logger.info("RUNNING SCAN...")
        logger.info("================================================================================")
        if args.recon:
            logger.info(f"[RECON] Mode: {args.recon_mode} | URLs discovered: {len(urls)}")
        else:
            logger.info(f"[*] Recon disabled | Using supplied targets: {len(urls)}")
        
        module = BlindSQLiModule(timeout=10)

        with ThreadPoolExecutor(max_workers=args.threads) as exe:
            futures = {exe.submit(module.scan_url, u): u for u in urls}
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        findings.extend(res)
                        logger.info("Findings on %s: %d", futures[fut], len(res))
                except Exception as e:
                    logger.debug("Scan task error: %s", e)

        write_outputs(findings)
        # Human-friendly console summary
        if findings:
            print_success(f"Found {len(findings)} SQLi findings")
            for idx, fnd in enumerate(findings, 1):
                param = fnd.get("parameter")
                inj = fnd.get("injection")
                conf = fnd.get("details", {}).get("confidence", "UNKNOWN")
                # For time-based, show first delta if present
                ev = fnd.get("details", {}).get("evidence", []) if isinstance(fnd.get("details"), dict) else []
                delta_txt = ""
                payload_snip = ""
                if inj.startswith("time") and ev:
                    base = ev[0].get("baseline")
                    inj_t = ev[0].get("t_inj")
                    if base is not None and inj_t is not None:
                        delta_txt = f" | Δ={inj_t - base:.2f}s"
                    payload_snip = format_payload_snippet(ev[0].get("payload", ""))
                elif inj.startswith("boolean") and ev:
                    payload_snip = format_payload_snippet(ev[0].get("payload_true", ""))
                print_info(f"[{idx}] {inj} on {param} | Confidence: {conf}{delta_txt}")
                if payload_snip:
                    print_info(f"    Payload: {payload_snip}")
        else:
            print_info("No SQLi findings confirmed.")
        logger.info("Scan complete. Total findings: %d", len(findings))

if __name__ == "__main__":
    main()
