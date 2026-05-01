import socket
import threading
from queue import Queue

# 1. Service Detection (Advanced)
def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

# 4. OS Fingerprinting
def guess_os(banner):
    banner = banner.lower()
    if "ubuntu" in banner or "debian" in banner:
        return "Linux (Ubuntu/Debian)"
    elif "win32" in banner or "microsoft" in banner:
        return "Windows"
    elif "centos" in banner or "redhat" in banner:
        return "Linux (CentOS/RHEL)"
    elif "nginx" in banner or "apache" in banner:
        return "Linux/Unix (Likely)"
    return "Unknown OS"

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1.5)
        s.connect((ip, port))
        if port in [80, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            s.send(b"Hello\r\n")
        
        banner = s.recv(1024).decode(errors='ignore').strip()
        
        for line in banner.splitlines():
            if "Server:" in line:
                return line.replace("Server:", "").strip()
        return banner.splitlines()[0][:40] if banner else "No Banner"
    except:
        return "No Banner"

# Multi-threading setup
print_lock = threading.Lock()
q = Queue()

def scan_worker(target_ip):
    while not q.empty():
        port = q.get()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        
        # connect_ex returns 0 if port is open
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            service = get_service_name(port)
            banner = banner_grab(target_ip, port)
            os_info = guess_os(banner) if banner != "No Banner" else "N/A"
            
            with print_lock:
                print(f"{port:<10} {service:<15} {banner[:35]:<40} {os_info}")
                with open("results.txt", "a") as f:
                    f.write(f"Port {port}: {service} | OS: {os_info} | Banner: {banner}\n")
        
        s.close()
        q.task_done()

def main():
    print("\n--- Python Pro Port Scanner ---")
    target = input("Enter target (IP or Domain): ")
    target = target.replace("http://", "").replace("https://", "").strip("/")
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Error: Could not resolve hostname.")
        return

    try:
        print("\n[Range Example: 1-1000]")
        port_range = input("Enter port range (start-end): ")
        start_port, end_port = map(int, port_range.split('-'))
    except ValueError:
        print("[!] Error: Use format '1-1000'.")
        return

    print(f"\nScanning {target_ip}...")
    print("-" * 90)
    print(f"{'PORT':<10} {'SERVICE':<15} {'BANNER':<40} {'OS GUESS'}")
    print("-" * 90)

    for port in range(start_port, end_port + 1):
        q.put(port)

    for _ in range(50):
        t = threading.Thread(target=scan_worker, args=(target_ip,))
        t.daemon = True
        t.start()

    q.join()
    print("-" * 90)
    print("Scan Completed! Results saved to 'results.txt'")

if __name__ == "__main__":
    main()