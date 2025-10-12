#!/usr/bin/env python3
import requests
import re
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Optional, Tuple

# --- Constants and Configuration ---
PLUGIN_SVN_URL = "https://plugins.svn.wordpress.org/{}/"
HEADERS = {
    "User-Agent": "WP-Unclaimed-Plugin-Scanner/1.1 (Community Tool for Ethical Security Research)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
}

# --- ANSI Color Codes for Better Output ---
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

# --- Core Functions ---

def extract_plugins_from_site(url: str, session: requests.Session) -> Tuple[str, Set[str]]:
    """
    Fetches a website's content and extracts unique WordPress plugin slugs.

    Args:
        url: The URL of the WordPress site to scan.
        session: The requests session object.

    Returns:
        A tuple containing the final URL (after redirects) and a set of found plugin slugs.
    """
    slugs: Set[str] = set()
    try:
        response = session.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
        response.raise_for_status()
        
        # Regex to find paths like wp-content/plugins/PLUGIN-SLUG/
        matches = re.findall(r"wp-content/plugins/([a-zA-Z0-9\-_]+)/", response.text)
        slugs.update(m.lower() for m in matches)

        # Use BeautifulSoup for more robust link/script tag parsing
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all(['link', 'script'], href=True) + soup.find_all(['script'], src=True):
            src_or_href = tag.get('href') or tag.get('src')
            if src_or_href and 'wp-content/plugins/' in src_or_href:
                match = re.search(r"wp-content/plugins/([a-zA-Z0-9\-_]+)/", src_or_href)
                if match:
                    slugs.add(match.group(1).lower())
                    
        return response.url, slugs
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}[!] Error scraping {url}: {e}{Colors.RESET}")
        return url, set()

def check_plugin_status(slug: str, session: requests.Session) -> Dict:
    """
    Checks if a plugin slug is claimed on the official WordPress repository.
    An unclaimed slug is one that results in a 404 error.

    Args:
        slug: The plugin slug to check.
        session: The requests session object.

    Returns:
        A dictionary with the check result.
    """
    check_url = PLUGIN_SVN_URL.format(slug)
    try:
        # A HEAD request is faster as we only need the status code
        response = session.head(check_url, headers=HEADERS, timeout=7)
        if response.status_code == 404:
            return {"slug": slug, "status": "unclaimed"}
        else:
            return {"slug": slug, "status": "claimed"}
    except requests.exceptions.RequestException:
        # If the check fails, assume it's claimed to avoid false positives
        return {"slug": slug, "status": "error"}

# --- Main Logic and Orchestration ---

def main():
    parser = argparse.ArgumentParser(
        description="WordPress Unclaimed Plugin Scanner. A tool to find potential dependency confusion vulnerabilities in WordPress sites by checking for unclaimed plugin slugs.",
        epilog="Use responsibly and only on sites you have explicit permission to test."
    )
    parser.add_argument('targets', nargs='*', help="One or more target URLs to scan.")
    parser.add_argument('-f', '--file', help="A file containing a list of target URLs (one per line).")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Number of concurrent threads to use (default: 10).")
    parser.add_argument('-o', '--output', help="File to save the results in JSON format.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Show all plugins found, including claimed ones.")
    args = parser.parse_args()

    # --- Load Targets ---
    targets = args.targets
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Error: The file '{args.file}' was not found.{Colors.RESET}")
            return
    
    if not targets:
        parser.print_help()
        return

    targets = sorted(list(set(targets))) # Ensure unique targets

    print(f"{Colors.BLUE}[*] Starting scan for {len(targets)} target(s) with {args.threads} threads...{Colors.RESET}")

    site_plugins: Dict[str, Set[str]] = {}
    all_unique_slugs: Set[str] = set()

    # --- Phase 1: Scrape all sites to gather plugin slugs ---
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {executor.submit(extract_plugins_from_site, url, session): url for url in targets}
            
            print(f"{Colors.BLUE}[*] Phase 1: Scraping sites to identify plugins...{Colors.RESET}")
            for i, future in enumerate(as_completed(future_to_url), 1):
                final_url, slugs = future.result()
                if slugs:
                    site_plugins[final_url] = slugs
                    all_unique_slugs.update(slugs)
                print(f"  > Scraped {i}/{len(targets)}: {future_to_url[future]} (found {len(slugs)} plugins)")

    if not all_unique_slugs:
        print(f"\n{Colors.GREEN}[*] Scan complete. No plugins were found across any of the targets.{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Phase 2: Checking the status of {len(all_unique_slugs)} unique plugins...{Colors.RESET}")
    
    # --- Phase 2: Check the status of each unique plugin ---
    plugin_statuses: Dict[str, str] = {}
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_slug = {executor.submit(check_plugin_status, slug, session): slug for slug in all_unique_slugs}
            
            for i, future in enumerate(as_completed(future_to_slug), 1):
                result = future.result()
                plugin_statuses[result['slug']] = result['status']
                print(f"  > Checked {i}/{len(all_unique_slugs)}: {result['slug']} -> {result['status']}", end='\r')
    
    print("\n") # Newline after the progress indicator

    # --- Phase 3: Correlate results and generate report ---
    vulnerable_sites: List[Dict] = []
    
    for site_url, slugs in site_plugins.items():
        unclaimed_for_site = [s for s in slugs if plugin_statuses.get(s) == 'unclaimed']
        
        if unclaimed_for_site:
            vulnerable_sites.append({
                "site": site_url,
                "unclaimed_plugins": sorted(unclaimed_for_site)
            })

    # --- Display Results ---
    if not vulnerable_sites:
        print(f"{Colors.GREEN}[+] Scan finished. No unclaimed plugin slugs found.{Colors.RESET}")
    else:
        print(f"{Colors.RED}[!!!] VULNERABILITIES FOUND [!!!]{Colors.RESET}")
        print("-" * 50)
        for result in vulnerable_sites:
            print(f"{Colors.YELLOW}Vulnerable Site:{Colors.RESET} {result['site']}")
            for plugin in result['unclaimed_plugins']:
                print(f"  {Colors.RED}  -> Unclaimed Plugin:{Colors.RESET} {plugin}")
                print(f"  {Colors.BLUE}     Claim URL:{Colors.RESET} https://wordpress.org/plugins/{plugin}/")
            print("-" * 50)

    if args.verbose:
        print(f"\n{Colors.BLUE}[*] Verbose Output: All Found Plugins{Colors.RESET}")
        for site_url, slugs in site_plugins.items():
            print(f"{Colors.YELLOW}Site:{Colors.RESET} {site_url}")
            for slug in sorted(list(slugs)):
                status = plugin_statuses.get(slug, 'unknown')
                color = Colors.RED if status == 'unclaimed' else Colors.GREEN if status == 'claimed' else Colors.YELLOW
                print(f"  - {slug} ({color}{status.upper()}{Colors.RESET})")
            print("-" * 50)

    # --- Save to File ---
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(vulnerable_sites, f, indent=4)
            print(f"\n{Colors.GREEN}[+] Results saved to {args.output}{Colors.RESET}")
        except IOError as e:
            print(f"{Colors.RED}[!] Error saving results to {args.output}: {e}{Colors.RESET}")


if __name__ == "__main__":
    main()