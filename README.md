# WordPress Unclaimed Plugin Scanner

A fast, concurrent scanner to detect potential dependency confusion vulnerabilities in WordPress websites by identifying unclaimed plugin slugs in the official WordPress.org repository.

This tool is intended for security researchers, bug bounty hunters, and WordPress administrators for **ethical and authorized security assessments only.**

---

### **Ethical Use Disclaimer**

⚠️ **Warning:** This tool performs active reconnaissance against target websites. Unauthorized scanning of websites is illegal in many jurisdictions. You must have explicit, written permission from the website owner before using this tool on any target that you do not own. The developers of this tool are not responsible for any misuse or damage caused by this script. **Use it at your own risk and for educational/authorized purposes only.**

---

## What is Dependency Confusion in WordPress?

When a WordPress site uses a custom or premium plugin that is not listed in the official WordPress.org plugin repository, a vulnerability can arise. If the plugin's unique name (its "slug") is available, an attacker could register a plugin with the same slug on WordPress.org.

Depending on the site's configuration and update mechanisms, it might automatically "update" to the attacker's malicious version from the official repository, leading to a full site compromise. This tool helps identify such unclaimed plugin slugs.

## Features

-   **Concurrent Scanning:** Uses multithreading to scan multiple sites and check plugins quickly.
-   **Efficient Logic:** Gathers all unique plugins first, then checks each plugin's status only once, even if found on multiple sites.
-   **Multiple Target Inputs:** Scan single URLs, multiple URLs, or provide a list of targets from a file.
-   **Flexible Output:** Clear, color-coded console output and the option to save results to a structured JSON file.
-   **Verbose Mode:** Option to view all discovered plugins and their claim status (claimed, unclaimed, or error).
-   **Robust Scraping:** Uses both Regex and BeautifulSoup for better plugin detection from HTML source.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/wp-unclaimed-plugin-scanner.git
    cd wp-unclaimed-plugin-scanner
    ```

2.  **Install dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

## Usage

```bash
python3 scanner.py [targets...] [options]
```

### Examples

**1. Scan a single target:**
```bash
python3 scanner.py https://example.com
```

**2. Scan multiple targets from the command line:**
```bash
python3 scanner.py https://site1.com https://site2.blog
```

**3. Scan targets from a file:**
Create a file `targets.txt` with one URL per line:
```
https://wordpress-site.org
https://another-blog.com
https://test-site.net
```
Then run the scanner:
```bash
python3 scanner.py -f targets.txt
```

**4. Increase concurrency and save vulnerable findings to a JSON file:**
```bash
python3 scanner.py -f targets.txt -t 20 -o vulnerable.json
```

**5. Run in verbose mode to see all discovered plugins:**
```bash
python3 scanner.py https://example.com -v
```

### Command-Line Options

| Flag                 | Description                                                  |
| -------------------- | ------------------------------------------------------------ |
| `targets` (positional) | One or more target URLs to scan.                           |
| `-f`, `--file`       | Path to a file containing a list of URLs, one per line.    |
| `-t`, `--threads`    | Number of concurrent threads to use. (Default: 10)           |
| `-o`, `--output`     | File to save vulnerable results in JSON format.              |
| `-v`, `--verbose`    | Show all plugins found and their status (claimed/unclaimed). |

## Example Output

### Standard Output

```
[!!!] VULNERABILITIES FOUND [!!!]
--------------------------------------------------
Vulnerable Site: https://example.com/
    -> Unclaimed Plugin: my-custom-plugin
       Claim URL: https://wordpress.org/plugins/my-custom-plugin/
--------------------------------------------------
```

### JSON Output (`-o results.json`)

```json
[
    {
        "site": "https://example.com/",
        "unclaimed_plugins": [
            "my-custom-plugin"
        ]
    }
]
```