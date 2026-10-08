"""
main.py — Command-Line Interface for the Phishing Email & Threat Analyzer.

Usage examples:
  python main.py                              # Interactive mode (paste email)
  python main.py -f email.txt                # Analyze a file
  python main.py -f email.txt --html         # + save HTML report
  python main.py -f email.txt --json         # + save JSON report
  python main.py --batch sample_emails/      # Analyze all .txt files in folder
  python main.py --history                   # Show past analyses
  python main.py --provider gemini -f e.txt  # Force Gemini instead of Groq
"""

import argparse
import sys
import os
import json

from config import validate_config, AI_PROVIDER
from analyzer import analyze_email
from utils import (
    print_banner, print_report, log_analysis,
    extract_urls_from_text, extract_headers,
    preprocess_email, ensure_dirs, load_history,
    BOLD, CYAN, GREEN, RED, YELLOW, RESET, DIM,
)
from report_generator import generate_html_report, generate_json_report


# ──────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="AI-Powered Phishing Email & Threat Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              Interactive (paste email)
  python main.py -f sample_emails/phishing_bank.txt --html
  python main.py --batch sample_emails/ --html --json
  python main.py --history
  python main.py --provider gemini -f email.txt
        """,
    )
    p.add_argument(
        "-f", "--file",
        metavar="PATH",
        help="Path to a .txt file containing the email to analyze",
    )
    p.add_argument(
        "--batch",
        metavar="FOLDER",
        help="Analyze all .txt files inside a folder",
    )
    p.add_argument(
        "--provider",
        choices=["groq", "gemini"],
        default=None,
        help=f"AI provider (default from .env: {AI_PROVIDER})",
    )
    p.add_argument(
        "--html",
        action="store_true",
        help="Save an HTML report to the reports/ folder",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Save a JSON report to the reports/ folder",
    )
    p.add_argument(
        "--history",
        action="store_true",
        help="Display past analysis history",
    )
    p.add_argument(
        "--no-log",
        action="store_true",
        help="Do not log this analysis to history",
    )
    return p


# ──────────────────────────────────────────────────────────────────────────────
# CORE WORKFLOW
# ──────────────────────────────────────────────────────────────────────────────

def run_analysis(email_text: str, args) -> dict:
    """Execute one full analysis cycle and handle output."""
    email_text = preprocess_email(email_text)

    if not email_text.strip():
        print(f"{RED}Error: Empty email text provided.{RESET}")
        return {}

    # Pre-analysis: extract metadata from the text itself
    found_urls   = extract_urls_from_text(email_text)
    headers      = extract_headers(email_text)

    print(f"\n{CYAN}  Analyzing email ({len(email_text)} chars) ...{RESET}")
    if headers.get("subject"):
        print(f"  Subject : {BOLD}{headers['subject']}{RESET}")
    if headers.get("from"):
        print(f"  From    : {headers['from']}")
    if found_urls:
        print(f"  URLs found in text: {len(found_urls)}")
    print()

    try:
        report = analyze_email(email_text, provider=args.provider)
    except (EnvironmentError, RuntimeError, TimeoutError, ValueError) as e:
        print(f"\n{RED}Analysis failed:{RESET} {e}\n")
        return {}

    # Display to terminal
    print_report(report)

    # Log to history
    if not args.no_log:
        log_analysis(email_text, report)

    # Optional reports
    if args.html:
        path = generate_html_report(email_text, report)
        print(f"{GREEN}  ✓ HTML report saved:{RESET} {path}")

    if args.json:
        path = generate_json_report(email_text, report)
        print(f"{GREEN}  ✓ JSON report saved:{RESET} {path}")

    return report


def run_batch(folder: str, args):
    """Analyze all .txt files in a folder and print a summary."""
    txt_files = [
        os.path.join(folder, f)
        for f in sorted(os.listdir(folder))
        if f.endswith(".txt")
    ]

    if not txt_files:
        print(f"{YELLOW}No .txt files found in '{folder}'{RESET}")
        return

    results = []
    print(f"\n{BOLD}Batch mode: {len(txt_files)} file(s) to analyze{RESET}\n")

    for i, filepath in enumerate(txt_files, 1):
        print(f"{DIM}{'─'*60}{RESET}")
        print(f"{CYAN}[{i}/{len(txt_files)}] {os.path.basename(filepath)}{RESET}")
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            email_text = f.read()
        report = run_analysis(email_text, args)
        if report:
            results.append({
                "file":       os.path.basename(filepath),
                "is_phishing":report.get("is_phishing"),
                "risk_score": report.get("risk_score"),
                "action":     report.get("recommended_action"),
            })

    # Batch summary table
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  BATCH SUMMARY{RESET}")
    print(f"{'─'*60}")
    print(f"  {'FILE':<35} {'PHISHING':<10} {'SCORE':<8} {'ACTION'}")
    print(f"{'─'*60}")
    for r in results:
        ph = f"{RED}YES{RESET}" if r["is_phishing"] else f"{GREEN}NO{RESET}"
        print(f"  {r['file']:<35} {ph:<18} {r['risk_score']:<8} {r['action']}")
    print(f"{'─'*60}")

    phishing_count = sum(1 for r in results if r["is_phishing"])
    print(f"  Phishing: {RED}{phishing_count}{RESET}/{len(results)}   "
          f"Legitimate: {GREEN}{len(results)-phishing_count}{RESET}/{len(results)}")
    print(f"{'═'*60}\n")


def show_history():
    """Print analysis history in a readable table."""
    history = load_history()
    if not history:
        print(f"{YELLOW}No analysis history found.{RESET}")
        return

    print(f"\n{BOLD}  ANALYSIS HISTORY ({len(history)} records){RESET}")
    print(f"{'─'*90}")
    print(f"  {'TIMESTAMP':<22} {'PHISHING':<10} {'SCORE':<7} {'CATEGORY':<20} {'ACTION'}")
    print(f"{'─'*90}")
    for h in history[-20:]:  # Show last 20
        ts  = h.get("timestamp", "")[:19].replace("T", " ")
        ph  = "YES" if h.get("is_phishing") else "NO"
        sc  = str(h.get("risk_score", "?"))
        cat = h.get("threat_category", "?")
        act = h.get("recommended_action", "?")[:25]
        ph_col = RED if h.get("is_phishing") else GREEN
        print(f"  {ts:<22} {ph_col}{ph:<10}{RESET} {sc:<7} {cat:<20} {act}")
    print(f"{'─'*90}")
    print(f"  Showing last 20 of {len(history)} total analyses.\n")


def interactive_mode(args):
    """Accept multi-line email paste from stdin."""
    print(f"{CYAN}Paste the email content below.")
    print(f"When done, press Enter twice, then type 'END' and press Enter.{RESET}")
    print(f"{DIM}{'─'*60}{RESET}")

    lines = []
    blank_count = 0
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        if line == "":
            blank_count += 1
        else:
            blank_count = 0
        lines.append(line)

    email_text = "\n".join(lines).strip()
    if not email_text:
        print(f"{RED}No email content entered. Exiting.{RESET}")
        sys.exit(0)

    run_analysis(email_text, args)


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ensure_dirs()
    print_banner()

    parser = build_parser()
    args   = parser.parse_args()

    # History view — no API needed
    if args.history:
        show_history()
        sys.exit(0)

    # Validate config (raises with helpful message if missing key)
    try:
        validate_config()
    except EnvironmentError as e:
        print(f"{RED}{e}{RESET}")
        sys.exit(1)

    # ── Route to correct mode ──
    if args.batch:
        if not os.path.isdir(args.batch):
            print(f"{RED}Error: '{args.batch}' is not a valid directory.{RESET}")
            sys.exit(1)
        run_batch(args.batch, args)

    elif args.file:
        if not os.path.isfile(args.file):
            print(f"{RED}Error: File not found: '{args.file}'{RESET}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            email_text = f.read()
        run_analysis(email_text, args)

    else:
        interactive_mode(args)


if __name__ == "__main__":
    main()
