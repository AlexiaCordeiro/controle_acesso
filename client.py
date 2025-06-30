import socket
import json
import random
import time
import os

class FileClient:
    def __init__(self, client_id, file_list, username=None, password=None, server_host='localhost', server_port=5000):
        self.client_id = client_id
        self.server_host = os.getenv('SERVER_HOST', server_host)
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected_files = set()
        self.file_list = file_list
        self.username = username
        self.password = password
        self.session_id = None

    def connect(self):
        print(f"[CLIENT {self.client_id}] Attempting to connect to {self.server_host}:{self.server_port}")
        try:
            self.socket.connect((self.server_host, self.server_port))
            print(f"[CLIENT {self.client_id}] Connected to {self.server_host}:{self.server_port}")
        except ConnectionRefusedError:
            print(f"[CLIENT {self.client_id}_ERROR] Connection refused. Is the server running on {self.server_host}:{self.server_port}?")
            raise
        except Exception as e:
            print(f"[CLIENT {self.client_id}_ERROR] An error occurred during connection: {e}")
            raise

    def send_request(self, request_payload):
        """Helper to send JSON requests and receive JSON responses."""
        request_json = json.dumps(request_payload)
        print(f"[CLIENT {self.client_id}] Sending request: {request_json}")
        try:
            self.socket.sendall(request_json.encode('utf-8'))
            print(f"[CLIENT {self.client_id}] Sent data. Waiting for response...")

            response_data = self.socket.recv(1024).decode('utf-8')
            print(f"[CLIENT {self.client_id}] Received raw response: {response_data}")
            return json.loads(response_data)
        except socket.error as e:
            print(f"[CLIENT {self.client_id}_ERROR] Socket error during request: {e}")
            return {"status": "error", "message": f"Socket error: {e}"}
        except json.JSONDecodeError as e:
            print(f"[CLIENT {self.client_id}_ERROR] JSON decode error on response: {e}, Raw: '{response_data}'")
            return {"status": "error", "message": f"JSON decode error: {e}"}
        except Exception as e:
            print(f"[CLIENT {self.client_id}_ERROR] Unexpected error in send_request: {e}")
            return {"status": "error", "message": f"Unexpected error: {e}"}

    def request_login(self):
        if not self.username or not self.password:
            print(f"[CLIENT {self.client_id}] No username or password set for login.")
            return {"status": "error", "message": "No login credentials."}

        request_payload = {
            "action": "login",
            "username": self.username,
            "password": self.password
        }
        print(f"[CLIENT {self.client_id}] Requesting login for user: {self.username}")
        response = self.send_request(request_payload)
        if response.get("status") == "success":
            self.session_id = response.get("session_id")
            print(f"[CLIENT {self.client_id}] Successfully logged in with session ID: {self.session_id}")
        else:
            print(f"[CLIENT {self.client_id}_ERROR] Login failed: {response.get('message')}")
        return response

    def request_access(self, filename, access_type):
        if not self.session_id:
            print(f"[CLIENT {self.client_id}_ERROR] Cannot request access, no active session.")
            return {"status": "error", "message": "No active session."}

        request_payload = {
            "action": "request_access",
            "filename": filename,
            "access_type": access_type,
            "client_id": self.client_id,
            "session_id": self.session_id
        }
        print(f"[CLIENT {self.client_id}] Requesting {access_type} access for {filename}.")
        return self.send_request(request_payload)

    def release_access(self, filename, access_type):
        if not self.session_id:
            print(f"[CLIENT {self.client_id}_ERROR] Cannot release access, no active session.")
            return {"status": "error", "message": "No active session."}

        request_payload = {
            "action": "release_access",
            "filename": filename,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "access_type": access_type
        }
        print(f"[CLIENT {self.client_id}] Releasing {access_type} access for {filename}.")
        return self.send_request(request_payload)

    def request_logout(self):
        if not self.username or not self.session_id:
            print(f"[CLIENT {self.client_id}] Not logged in or no session to logout.")
            return {"status": "error", "message": "Not logged in."}

        request_payload = {
            "action": "logout",
            "username": self.username,
            "session_id": self.session_id
        }
        print(f"[CLIENT {self.client_id}] Requesting logout for user: {self.username}")
        response = self.send_request(request_payload)
        if response.get("status") == "success":
            self.session_id = None
            print(f"[CLIENT {self.client_id}] Successfully logged out.")
        else:
            print(f"[CLIENT {self.client_id}_ERROR] Logout failed: {response.get('message')}")
        return response

    def simulate_work(self, max_operations=5):
        print(f"[CLIENT {self.client_id}] Starting simulation with {max_operations} operations.")

        try:
            self.connect()

            login_resp = self.request_login()
            if login_resp.get("status") != "success":
                print(f"[CLIENT {self.client_id}_ERROR] Failed to log in. Aborting simulation. Response: {login_resp}")
                return # Stop simulation if login fails

            for i in range(max_operations):
                action = random.choice(["read", "write"])
                file_name = random.choice(self.file_list)

                print(f"[CLIENT {self.client_id}] Operation {i+1}/{max_operations}: Requesting {action} access to {file_name}.")
                response = self.request_access(file_name, action)
                print(f"[CLIENT {self.client_id}] Received access response for {file_name} ({action}): {response}")

                if response and response.get('status') == 'granted':
                    print(f"[CLIENT {self.client_id}] Working on {file_name} ({action}) for some seconds...")
                    work_time = random.randint(1, 5)
                    time.sleep(work_time)

                    release_resp = self.release_access(file_name, action)
                    print(f"[CLIENT {self.client_id}] Released {file_name} ({action}). Response: {release_resp}")
                else:
                    print(f"[CLIENT {self.client_id}] Access {action} to {file_name} was {response.get('status')}. Message: {response.get('message')}")

                time.sleep(random.uniform(0.5, 2.0)) # Pause between operations

            logout_resp = self.request_logout()
            print(f"[CLIENT {self.client_id}] Logout attempt response: {logout_resp}")

        except ConnectionRefusedError:
            print(f"[CLIENT {self.client_id}_FATAL] Connection refused. Is the server running?")
        except Exception as e:
            print(f"[CLIENT {self.client_id}_FATAL] Encountered an error during simulation: {e}")
        finally:
            self.disconnect()

    def disconnect(self):
        if self.socket:
            print(f"[CLIENT {self.client_id}] Disconnecting socket.")
            self.socket.close()
            self.socket = None
        print(f"[CLIENT {self.client_id}] Connection closed.")


if __name__ == "__main__":
    print("[MAIN] Client script started.")
    # Configuration for the simulation
    FILES = ["fileA", "fileB", "fileC"] # Match server's files

    # Get client_id from environment variable (Docker container hostname)
    container_client_id = os.getenv('HOSTNAME', 'default_client')

    # Assign usernames and passwords based on client_id or use a rotating pool
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

    print(f"[MAIN] Starting client {container_client_id} with user {client_user}")

    client = FileClient(
        client_id=container_client_id,
        file_list=FILES,
        username=client_user,
        password=client_pass,
        server_host='file-server' # Use the service name defined in docker-compose.yml
    )

    client.simulate_work(max_operations=5)
    print(f"[MAIN] Client {container_client_id} simulation finished.")
