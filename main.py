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

def write_outputs(findings, out_dir=OUTPUT_DIR):
    json_path = os.path.join(out_dir, "findings.json")
    txt_path = os.path.join(out_dir, "findings.txt")
    with open(json_path, "w") as f:
        json.dump(findings, f, indent=2)
    with open(txt_path, "w") as f:
        for item in findings:
            f.write(f"URL: {item.get('url')}\n")
            f.write(f"Parameter: {item.get('parameter')}\n")
            f.write(f"Type: {item.get('injection')}\n")
            f.write(f"Details: {json.dumps(item.get('details'))}\n")
            f.write("-" * 40 + "\n")
    logger.info("Wrote results to %s and %s", json_path, txt_path)

def main():
    ap = argparse.ArgumentParser(description="B-SQLi - Blind SQL Injection Detection Framework")
    ap.add_argument("-u", "--url", help="Target domain (e.g., example.com)", required=False)
    ap.add_argument("-f", "--file", "--urls", help="File with URLs", required=False, dest="file")
    ap.add_argument("--recon", action="store_true", help="Run recon (gau + gf)")
    ap.add_argument("--scan", choices=["sqli", "bxss"], help="Module to scan (sqli or bxss)")
    ap.add_argument("--threads", type=int, default=THREADS)
    ap.add_argument("--listener", help="Callback server URL for BXSS (e.g., http://attacker.com:5000)", required=False)
    ap.add_argument("--wait", type=int, default=30, help="Wait time (seconds) for BXSS callbacks after scan")
    ap.add_argument("--raw", help="Raw HTTP request file (sqlmap -r style) for direct scan", required=False)
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

    if not args.recon:
        logger.error("This workflow requires --recon to collect parameterized URLs.")
        return

    if not args.url and not args.file:
        logger.error("Provide -u domain or -f/--urls file")
        return
    
    # BXSS requires listener URL
    if args.scan == "bxss" and not args.listener:
        print_error("BXSS scan requires --listener URL (e.g., http://attacker.com:5000)")
        return

    from_file = bool(args.file)
    src = args.file if from_file else args.url
    
    # Determine scan type for recon filtering
    scan_type = args.scan if args.scan else "sqli"
    urls = gather_parameterized_urls(src, from_file=from_file, scan_type=scan_type)
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
        logger.info("Scan complete. Total findings: %d", len(findings))

if __name__ == "__main__":
    main()
