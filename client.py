# client.py

import socket
import json
import random
import time
import os # Importar o módulo os para acessar variáveis de ambiente

class FileClient:
    # Changed __init__ to accept file_list and optionally username/password for login
    def __init__(self, client_id, file_list, username=None, password=None, server_host='localhost', server_port=5000):
        self.client_id = client_id
        self.server_host = os.getenv('SERVER_HOST', server_host)
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected_files = set() # This seems unused in your current simulate_work logic
        self.file_list = file_list # Store the list of files here
        self.username = username
        self.password = password
        self.session_id = None # To store session ID after login

    def connect(self):
        print(f"Client {self.client_id} attempting to connect to {self.server_host}:{self.server_port}")
        self.socket.connect((self.server_host, self.server_port))
        print(f"Client {self.client_id} connected to {self.server_host}:{self.server_port}")

    def send_request(self, request_payload):
        """Helper to send JSON requests and receive JSON responses."""
        request_json = json.dumps(request_payload)
        print(f"Client {self.client_id}: Sending request: {request_json}") # Added for verbose logging
        try:
            self.socket.sendall(request_json.encode('utf-8'))
            print(f"Client {self.client_id}: Sent data. Waiting for response...") # Added for verbose logging

            response_data = self.socket.recv(1024).decode('utf-8')
            print(f"Client {self.client_id}: Received raw response: {response_data}") # Added for verbose logging
            return json.loads(response_data)
        except socket.error as e:
            print(f"Client {self.client_id}: Socket error during request: {e}")
            return {"status": "error", "message": f"Socket error: {e}"}
        except json.JSONDecodeError as e:
            print(f"Client {self.client_id}: JSON decode error on response: {e}, Raw: '{response_data}'")
            return {"status": "error", "message": f"JSON decode error: {e}"}
        except Exception as e:
            print(f"Client {self.client_id}: Unexpected error in send_request: {e}")
            return {"status": "error", "message": f"Unexpected error: {e}"}

    def request_login(self):
        if not self.username or not self.password:
            print(f"Client {self.client_id}: No username or password set for login.")
            return {"status": "error", "message": "No login credentials."}
        
        request_payload = {
            "action": "login",
            "username": self.username,
            "password": self.password
        }
        response = self.send_request(request_payload)
        if response.get("status") == "success":
            self.session_id = response.get("session_id")
            print(f"Client {self.client_id}: Successfully logged in with session ID: {self.session_id}")
        return response

    def request_access(self, filename, access_type):
        request_payload = {
            "action": "request_access",
            "filename": filename,
            "access_type": access_type, # 'read' or 'write'
            "client_id": self.client_id, # For server logging
            "session_id": self.session_id # Pass session ID for server validation
        }
        return self.send_request(request_payload)

    def release_access(self, filename):
        request_payload = {
            "action": "release_access",
            "filename": filename,
            "client_id": self.client_id, # For server logging
            "session_id": self.session_id # Pass session ID for server validation
        }
        return self.send_request(request_payload)

    def request_logout(self):
        if not self.username or not self.session_id:
            print(f"Client {self.client_id}: Not logged in or no session to logout.")
            return {"status": "error", "message": "Not logged in."}
        
        request_payload = {
            "action": "logout",
            "username": self.username,
            "session_id": self.session_id
        }
        response = self.send_request(request_payload)
        if response.get("status") == "success":
            self.session_id = None # Clear session on successful logout
            print(f"Client {self.client_id}: Successfully logged out.")
        return response

    def simulate_work(self, max_operations=5):
        print(f"Starting simulation for client {self.client_id}")

        try:
            self.connect()

            # First, attempt to log in
            login_resp = self.request_login()
            if login_resp.get("status") != "success":
                print(f"Client {self.client_id}: Failed to log in. Aborting simulation. Response: {login_resp}")
                return # Stop simulation if login fails

            for i in range(max_operations):
                action = random.choice(["read", "write"])
                file_name = random.choice(self.file_list) # Use self.file_list

                print(f"Client {self.client_id} requesting {action} access to {file_name}")

                response = self.request_access(file_name, action)
                print(f"Client {self.client_id} received access response: {response}")

                if response and response.get('status') == 'granted':
                    print(f"Client {self.client_id} working on {file_name} ({action}) for X seconds")
                    work_time = random.randint(1, 5)
                    time.sleep(work_time)
                    
                    release_resp = self.release_access(file_name)
                    print(f"Client {self.client_id} released {file_name}. Response: {release_resp}")
                else:
                    print(f"Client {self.client_id} access {action} to {file_name} was {response.get('status')}. Message: {response.get('message')}")

                time.sleep(random.uniform(0.5, 2.0)) # Pause between operations
            
            # After all operations, attempt to log out
            logout_resp = self.request_logout()
            print(f"Client {self.client_id}: Logout attempt response: {logout_resp}")

        except ConnectionRefusedError:
            print(f"Client {self.client_id}: Connection refused. Is the server running?")
        except Exception as e:
            print(f"Client {self.client_id} encountered an error during simulation: {e}")
        finally:
            self.disconnect() # Ensure socket is closed

    def disconnect(self):
        if self.socket:
            print(f"Client {self.client_id}: Disconnecting socket.")
            self.socket.close()
            self.socket = None
        print(f"Client {self.client_id} connection closed.")

if __name__ == "__main__":
    # Configuration for the simulation
    FILES = ["fileA", "fileB", "fileC"] # Match server's files
    
    # Get client_id from environment variable (Docker container hostname)
    container_client_id = os.getenv('HOSTNAME', 'default_client')

    # Assign usernames and passwords based on client_id or use a rotating pool
    # For simplicity, let's assign specific credentials to specific container hostnames
    # This assumes your docker-compose service names are file-client-1, file-client-2, etc.
    # or you explicitly set a CLIENT_USER env var.
    
    username_map = {
        'file-client-1': 'user1',
        'file-client-2': 'user2',
        'file-client-3': 'user3',
        'default_client': 'user1' # Fallback for local testing or unassigned clients
    }
    password_map = {
        'file-client-1': 'password1',
        'file-client-2': 'password2',
        'file-client-3': 'password3',
        'default_client': 'password1'
    }

    client_user = username_map.get(container_client_id, 'user1')
    client_pass = password_map.get(container_client_id, 'password1')


    print(f"Starting simulation for client {container_client_id} with user {client_user}")
    
    client = FileClient(
        client_id=container_client_id, 
        file_list=FILES,
        username=client_user,
        password=client_pass,
        server_host='file-server' # Use the service name defined in docker-compose.yml
    )
    
    client.simulate_work(max_operations=5) # Call the class method correctly
