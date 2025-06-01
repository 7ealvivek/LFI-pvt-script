# LFI-pvt-script


Use Case for "Vivek Fetcher + Bulk LFI Scanner"

1. Purpose:

This script is designed for security researchers, penetration testers, and bug bounty hunters to automate the process of:

    Discovering URLs: Aggregating URLs associated with one or more target domains using popular reconnaissance tools (Katana, gau, gauplus, waybackurls, waymore).

    Scanning for Local File Inclusion (LFI) vulnerabilities: Testing each discovered (or provided) URL against a list of common LFI payloads to identify potential vulnerabilities.

    Efficient Asynchronous Operations: Performing these tasks asynchronously for speed and efficiency, handling many requests concurrently.

    Notification: Providing real-time notifications via Slack when a potential LFI vulnerability is found.

2. Who Would Use It?

    Penetration Testers: During web application security assessments to quickly identify LFI vulnerabilities across a broad scope.

    Bug Bounty Hunters: To efficiently scan large sets of domains/URLs for LFI bugs as part of their hunting process.

    Security Teams: For automated, periodic checks of their own web applications for LFI regressions.

3. Problem It Solves:

Manually collecting URLs and testing for LFI across multiple targets is time-consuming and tedious. This script automates these steps, allowing users to:

    Save significant time and effort in reconnaissance and vulnerability testing.

    Achieve wider coverage by testing many URLs and payloads systematically.

    Improve the speed of finding vulnerabilities through concurrent scanning.

    Get immediate alerts for critical findings, enabling faster response/reporting.

4. How to Run It (Example):

Prerequisites:

    Python 3.7+

    The aiohttp and colorama Python libraries (pip install aiohttp colorama).

    The reconnaissance tools installed and in your system's PATH:

        katana

        gau

        gauplus

        waybackurls

        waymore

Input Files:

    payloads.txt (Required): A text file where each line is an LFI payload.
    Example payloads.txt:

          
    ../../../../../../../../../../etc/passwd
    ../../../../../../../../../../windows/win.ini
    WEB-INF/web.xml
    WEB-INF/config.xml

        

    IGNORE_WHEN_COPYING_START

Use code with caution.
IGNORE_WHEN_COPYING_END

domains.txt (Optional, if using -dL): A text file where each line is a domain name.
Example domains.txt:

      
example.com
anotherdomain.org
test-site.net

    

IGNORE_WHEN_COPYING_START
Use code with caution.
IGNORE_WHEN_COPYING_END

urls.txt (Optional, if using -uL): A text file where each line is a full URL to scan.
Example urls.txt:

      
http://example.com/page.php?file=
https://anotherdomain.org/app/show.asp?view=
http://test-site.net/get_resource.jsp?name=

    

IGNORE_WHEN_COPYING_START

    Use code with caution.
    IGNORE_WHEN_COPYING_END

Example Commands:

    Scan a single domain:

          
    python vivek_scanner.py -d example.com -p payloads.txt --slack-webhook "YOUR_SLACK_WEBHOOK_URL"

        

    IGNORE_WHEN_COPYING_START

Use code with caution. Bash
IGNORE_WHEN_COPYING_END

Scan a list of domains from a file:

      
python vivek_scanner.py -dL domains.txt -p payloads.txt -b 200 -bd 1 -t 2.0 -r 2

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

(Here, batch size is 200, delay between batches is 1s, request timeout is 2s, and 2 retries)

Scan a list of URLs directly from a file (skip discovery):

      
python vivek_scanner.py -uL urls.txt -p payloads.txt

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

Set Slack webhook via environment variable:

      
export SLACK_WEBHOOK_URL="YOUR_SLACK_WEBHOOK_URL"
python vivek_scanner.py -d example.com -p payloads.txt

    

IGNORE_WHEN_COPYING_START

    Use code with caution. Bash
    IGNORE_WHEN_COPYING_END

5. Expected Output:

    Console Output:

        Progress of URL collection from different tools.

        Total URLs collected.

        Progress of the LFI scan (requests attempted, successes, failures, timeouts).

        A summary at the end with total counts.

        Green [HIT] messages for successful LFI findings.

    write-poc.txt file:

        Created in the same directory as the script.

        Appends a line for each successful LFI hit, including the base URL, the payload used, the user-agent, and the full target URL that was vulnerable.
        Example content of write-poc.txt:

          
    Success: http://vulnerable.com/index.php?page= - Payload: ../../etc/passwd - UA: Mozilla/5.0 (...) - Target URL: http://vulnerable.com/index.php?page=/../../etc/passwd

        

    IGNORE_WHEN_COPYING_START

    Use code with caution.
    IGNORE_WHEN_COPYING_END

    Slack Notifications (if configured):

        An alert message sent to the specified Slack channel for each critical LFI found, containing the vulnerable URL, payload, and base URL.

This comprehensive use case should give you a clear understanding of how to utilize and benefit from the script.
