import argparse
from recon.recon_manager import gather_parameterized_urls
from bsqli.modules.blind_sqli.sqli_module import BlindSQLiModule
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import time
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
  # SQLi scan with recon (discover URLs first)
  python main.py -u example.com --recon --scan sqli --threads 5
  
  # SQLi scan from URL file
  python main.py -f targets.txt --scan sqli --threads 10
  
  # Blind XSS scan with ngrok callback server
  python main.py -f targets.txt --scan bxss --listener https://abc123.ngrok.io --wait 120
  
  # Raw HTTP request (sqlmap style)
  python main.py --raw request.txt
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
        help="Run reconnaissance first: fetch URLs with gau, filter with gf patterns, score by parameter risk"
    )
    ap.add_argument(
        "--scan",
        choices=["sqli", "bxss"],
        help="Scan module: 'sqli' for Blind SQL Injection, 'bxss' for Blind XSS",
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
        help="Callback server URL for BXSS detection (required for BXSS scans). Use ngrok, Interactsh, or your own server (e.g., https://abc123.ngrok.io or http://attacker.com:5000)",
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

    if not args.url and not args.file:
        print_error("Missing target! Provide either:")
        print("  -u DOMAIN/URL     for single target with recon")
        print("  -f FILE           for batch scanning from file")
        print("\nRun: python main.py -h for examples")
        return
    
    # BXSS requires listener URL
    if args.scan == "bxss" and not args.listener:
        print_error("BXSS scan requires --listener URL")
        print("Examples:")
        print("  --listener https://abc123.ngrok.io     (use ngrok)")
        print("  --listener https://interactsh.com      (Interactsh)")
        print("  --listener http://your-server:5000     (your own server)")
        return

    from_file = bool(args.file)
    
    # If using file, recon is optional (URLs already provided)
    if from_file:
        if args.recon:
            # Recon mode: run gau+gf on domains in file
            src = args.file
            scan_type = args.scan if args.scan else "sqli"
            urls = gather_parameterized_urls(src, from_file=True, scan_type=scan_type)
        else:
            # Direct mode: read URLs from file
            try:
                with open(args.file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print_info(f"Loaded {len(urls)} URLs from {args.file}")
            except Exception as e:
                print_error(f"Failed to read file {args.file}: {e}")
                return
    else:
        # Domain mode: recon is required
        if not args.recon:
            print_error("When using -u/--url, --recon flag is required to discover URLs")
            print("Run with: python main.py -u example.com --recon --scan sqli")
            return
        src = args.url
        scan_type = args.scan if args.scan else "sqli"
        urls = gather_parameterized_urls(src, from_file=False, scan_type=scan_type)
    if not urls:
        print_error("No parameterized URLs found.")
        return

    findings = []
    
    # Route to appropriate module
    if args.scan == "bxss":
        print_header("BLIND XSS SCAN MODE")
        print_info(f"Listener URL: {args.listener}")
        print_info(f"Recon produced {len(urls)} parameterized URLs")
        
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
    
    else:  # sqli (default)
        logger.info("================================================================================")
        logger.info("RUNNING SCAN...")
        logger.info("================================================================================")
        logger.info(f"Recon produced {len(urls)} parameterized URLs")
        
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
