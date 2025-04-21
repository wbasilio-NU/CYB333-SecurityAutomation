#Part 2: Create a Port Scanner that can:
# - Scan a specified range of ports on a target host
# - Identify open ports
# - Handle conncections appropriately
# - Include proper error handling
# - Include comments to explain the code
# - Follow Python best practices
import socket

def port_scanner(target_host, start_port=None, end_port=None, specific_ports=None):
    """
    Scans a range of ports or specific ports on a target host to identify open ports.
    """
    target_host = 'localhost' if target_host == '' else target_host
    if specific_ports:
        ports_to_scan = [int(port) for port in specific_ports.split(',') if port.isdigit()]
    else:
        start_port = int(start_port) if start_port and start_port.isdigit() else 1
        end_port = int(end_port) if end_port and end_port.isdigit() else 65535
        ports_to_scan = range(start_port, end_port + 1)

    print(f"Scanning {target_host} on ports: {', '.join(map(str, ports_to_scan))}...")
    
    for port in ports_to_scan:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Set a timeout for the connection attempt
            try:
                result = sock.connect_ex((target_host, port))
                if result == 0:
                    print(f"Port {port} is open")
                else:
                    print(f"Port {port} is closed")
            except socket.error as e:
                print(f"Error connecting to port {port}: {e}")

if __name__ == "__main__":
    # Example usage of the port scanner
    target_host = input("Enter the target host (or leave blank for localhost): ") #The hostname or IP address of the target host
    mode = input("Choose scan mode (range/specific): ").strip().lower()
    
    if mode == "range":
        start_port = input("Enter the starting port (default is 1): ") #The starting port number for the scan
        end_port = input("Enter the ending port (default is 65535): ") #The ending port number for the scan
        port_scanner(target_host, start_port=start_port, end_port=end_port)
    elif mode == "specific":
        specific_ports = input("Enter specific ports to scan (comma-separated, e.g., 22,80,443): ") #A list of specific ports to scan
        port_scanner(target_host, specific_ports=specific_ports)
    else:
        print("Error! Invalid input.")