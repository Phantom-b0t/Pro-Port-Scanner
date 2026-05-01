# Python Pro Port Scanner
A high-performance, multi-threaded network security tool built with Python for rapid reconnaissance.

## Features
- **Multi-threading:** Leverages Python's `threading` module to scan 50+ ports simultaneously for maximum efficiency.
- **Service Detection:** Identifies open services using standard socket libraries to map target environments.
- **Banner Grabbing:** Extracts server header information to assist in OS fingerprinting and version detection[cite: 3].
- **Output Logging:** Automatically sanitizes and saves scan results to `results.txt` for further analysis[cite: 3].

## How to Run
1. **Clone the repo:**
   `git clone https://github.com/YourUsername/Pro-Port-Scanner.git`
2. **Run the script:**
   `python port_scanner.py`
3. **Usage:** Enter the target IP address and the desired port range when prompted.
