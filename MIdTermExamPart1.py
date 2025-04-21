# Midterm Exam Project CYB 333-Security Automatioin
# Part 1: Create a Python script that establishes a socket connection.
# requirements:
# - Create a basic client-server communication system using two Python scripts
# - - The server script should listen for incoming connections
# - - The client script should connect to the server
# - Demostrate proper socket intiailization and connection handling
# - Include appropriate error handling for socket operations
# - Include comments to explain the code
# - Follow Python best practices 
import socket

def start_server(host='localhost', port=65432, timeout=15):
    """
    Starts a TCP server that listens for incoming connections.
    """
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port)) # Bind the server to the host and port
        server_socket.listen() # Puts socket into listening mode for incoming connections
        server_socket.settimeout(timeout)  # Set timeout for listening state
        print(f"Server listening on {host}:{port}...")
        
        try:
            while True:
                conn, addr = server_socket.accept()
                with conn:
                    print(f"Connected by {addr}")
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"Received data: {data.decode()}")
                    conn.sendall(data)  # Echos back the received data
        except socket.timeout:
            print(f"Server timed out after {timeout} seconds of listening.")
        except Exception as e:
            print(f"Error: {e}")

def connect_to_server(host='scanme.org', port=80):
    """
    Connects to a server and sends an HTTP request.
    """
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((host, port))
            print(f"Connected to {host}:{port}")
            
            # HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            client_socket.sendall(request.encode())
            
            response = b""
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                response += data
            
            print(f"Received response:\n{response.decode('utf-8', errors='replace')}")
        
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    mode = input("Choose mode (server/client): ").strip().lower()
    
    if mode == "server":
        host = 'localhost' # Hostname for the server
        port = 65432 # Port number for the server
        timeout = 15  # Timeout duration in seconds
        start_server(host, port, timeout) # Start the server
    elif mode == "client":
        connect_to_server()
    else:
        print("Error Invalid Input.")
