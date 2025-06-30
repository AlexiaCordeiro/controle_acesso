import socket
import threading
import json
import time
import random # Needed for session_id generation
from collections import defaultdict, deque

class FileServer:
    def __init__(self, host='0.0.0.0', port=5000):
        print("FileServer __init__ called.")
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Socket created and options set.")

        try:
            self.server_socket.bind((self.host, self.port))
            print(f"Socket bound to {self.host}:{self.port}")
        except socket.error as e:
            print(f"Error binding socket: {e}")
            raise # Re-raise to ensure script stops and shows error

        self.server_socket.listen(5) # Allow up to 5 queued connections
        print(f"Server listening on {self.host}:{self.port}")

        self.users = {
            "user1": {"password": "password1", "roles": ["admin"]},
            "user2": {"password": "password2", "roles": ["user"]},
            "user3": {"password": "password3", "roles": ["guest"]}
        }
        self.files = {
            "fileA": {"owner": "user1", "permissions": {"read": ["admin", "user", "guest"], "write": ["admin", "user"]}},
            "fileB": {"owner": "user2", "permissions": {"read": ["admin", "user"], "write": ["admin"]}},
            "fileC": {"owner": "user1", "permissions": {"read": ["admin"], "write": ["admin"]}}
        }
        self.logged_in_users = {} # {username: {session_id: ..., role: ..., addr: ...}}
        self.log_file = "server_log.txt"
        self.log_lock = threading.Lock() # For safe concurrent writing to log file

        # Initialize access history for each file
        self.file_access_history = {file_name: deque(maxlen=10) for file_name in self.files}
        # { 'fileA': deque([ (timestamp, user, type, status), ... ]) }

        self.init_log()
        print("FileServer initialization complete.")


    def init_log(self):
        print("init_log called.")
        with self.log_lock:
            with open(self.log_file, "a") as f:
                f.write(f"[{time.ctime()}] Server started at {self.host}:{self.port}\n")
        print("Server started message logged.")

    def log_event(self, event):
        # print(f"Logging event: {event}") # Keep this if you want verbose internal logging
        with self.log_lock:
            with open(self.log_file, "a") as f:
                f.write(f"[{time.ctime()}] {event}\n")

    def authenticate_user(self, username, password, addr):
        print(f"Server: Attempting to authenticate user '{username}' from {addr}")
        if username in self.users and self.users[username]["password"] == password:
            if username in self.logged_in_users:
                # User already logged in, maybe from a different session?
                self.log_event(f"User {username} attempted login from {addr} but already logged in.")
                return {"status": "error", "message": "User already logged in."}

            session_id = f"{username}_{int(time.time())}_{random.randint(1000, 9999)}"
            self.logged_in_users[username] = {
                "session_id": session_id,
                "role": self.users[username]["roles"][0], # Assuming first role is primary
                "addr": addr
            }
            self.log_event(f"User {username} successfully logged in from {addr} with session {session_id}.")
            print(f"Server: User {username} logged in. Session: {session_id}")
            return {"status": "success", "message": "Login successful.", "session_id": session_id}
        else:
            self.log_event(f"Failed login attempt for '{username}' from {addr}.")
            print(f"Server: Failed login for '{username}'.")
            return {"status": "denied", "message": "Invalid username or password."}

    def logout_user(self, username, session_id):
        print(f"Server: Attempting to log out user '{username}' with session '{session_id}'")
        if username in self.logged_in_users and self.logged_in_users[username]["session_id"] == session_id:
            del self.logged_in_users[username]
            self.log_event(f"User {username} successfully logged out with session {session_id}.")
            print(f"Server: User {username} logged out.")
            return {"status": "success", "message": "Logout successful."}
        else:
            self.log_event(f"Failed logout attempt for '{username}' with invalid session {session_id}.")
            print(f"Server: Failed logout for '{username}' - invalid session.")
            return {"status": "error", "message": "User not logged in or invalid session."}

    def check_file_access(self, username, user_role, filename, access_type):
        print(f"Server: Checking {access_type} access for '{username}' ({user_role}) on '{filename}'")
        if filename not in self.files:
            return {"status": "denied", "message": f"File '{filename}' not found."}

        file_info = self.files[filename]
        required_permissions = file_info["permissions"].get(access_type, [])

        if user_role in required_permissions:
            print(f"Server: Access {access_type} granted to '{username}' for '{filename}'.")
            return {"status": "granted", "message": f"{access_type.capitalize()} access granted for {filename}."}
        else:
            print(f"Server: Access {access_type} denied to '{username}' for '{filename}'. Role '{user_role}' not in required permissions: {required_permissions}.")
            return {"status": "denied", "message": f"{access_type.capitalize()} access denied for {filename}. Insufficient permissions."}

    def record_file_access(self, filename, username, access_type, status):
        print(f"Server: Recording access: {filename} by {username} for {access_type} status {status}")
        if filename in self.file_access_history:
            self.file_access_history[filename].append((time.time(), username, access_type, status))
            self.log_event(f"File access recorded: {filename} by {username} ({access_type}, {status}).")
        else:
            self.log_event(f"Attempted to record access for unknown file: {filename}")

    def handle_client(self, conn, addr):
        current_user = None
        session_id = None
        print(f"Server: Handling client {addr}")
        self.log_event(f"New connection from {addr}")

        try:
            while True:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    print(f"Server: Client {addr} disconnected gracefully.")
                    self.log_event(f"Client {addr} disconnected gracefully.")
                    if current_user and session_id:
                        # Clean up logged-in user session if disconnected gracefully
                        self.logged_in_users.pop(current_user, None)
                        self.log_event(f"User {current_user} session {session_id} removed on disconnect.")
                    break

                request = {} # Initialize request to an empty dict
                response_data = {"status": "error", "message": "Invalid request format."} # Default error response

                try:
                    request = json.loads(data)
                    print(f"Server: Received request from {addr}: {request}")
                    self.log_event(f"Received request from {addr}: {request}")

                    action = request.get("action")

                    if action == "login":
                        username = request.get("username")
                        password = request.get("password")
                        response_data = self.authenticate_user(username, password, addr)
                        if response_data.get("status") == "success":
                            current_user = username
                            session_id = response_data.get("session_id")
                            # Update logged_in_users with comprehensive session info, including addr
                            if username in self.users: # Ensure user exists
                                self.logged_in_users[username] = {
                                    "session_id": session_id,
                                    "role": self.users[username]["roles"][0],
                                    "addr": addr # Store client address
                                }
                                self.log_event(f"User {username} logged in with session {session_id} from {addr}")

                    elif action == "request_access":
                        # Validate session before processing access request
                        if not current_user or self.logged_in_users.get(current_user, {}).get("session_id") != session_id:
                            response_data = {"status": "denied", "message": "Not logged in or invalid session for access request."}
                        else:
                            filename = request.get("filename")
                            access_type = request.get("access_type")
                            
                            user_role = None
                            # Retrieve role from currently active logged_in_users
                            if current_user in self.logged_in_users and self.logged_in_users[current_user]["session_id"] == session_id:
                                user_role = self.logged_in_users[current_user]["role"]
                            
                            if user_role:
                                response_data = self.check_file_access(current_user, user_role, filename, access_type)
                                self.log_event(f"Access request for {filename} by {current_user} ({user_role}) for {access_type} access: {response_data.get('status')}")
                                
                                if response_data.get('status') == 'granted':
                                    self.record_file_access(filename, current_user, access_type, "granted")
                                else:
                                    self.record_file_access(filename, current_user, access_type, "denied")
                            else:
                                response_data = {"status": "denied", "message": "Invalid user role or session."}

                    elif action == "release_access":
                        if not current_user or self.logged_in_users.get(current_user, {}).get("session_id") != session_id:
                            response_data = {"status": "error", "message": "Not logged in or invalid session for release request."}
                        else:
                            filename = request.get("filename")
                            response_data = {"status": "success", "message": f"Access to {filename} released by {current_user}."}
                            self.log_event(f"Release request for {filename} by {current_user}.")

                    elif action == "logout":
                        if current_user:
                            response_data = self.logout_user(current_user, session_id)
                            # Only clear current_user/session_id if logout was successful
                            if response_data.get("status") == "success":
                                current_user = None
                                session_id = None
                        else:
                            response_data = {"status": "error", "message": "No user logged in for this session to logout."}

                    else:
                        response_data = {"status": "error", "message": "Unknown action."}

                except json.JSONDecodeError as e:
                    response_data = {"status": "error", "message": f"JSON decoding error: {e}"}
                    print(f"Server: JSON decode error from {addr}: {e}, Raw data: '{data}'")
                    self.log_event(f"JSON decode error from {addr}: {e}, Raw data: '{data}'")
                except Exception as e:
                    response_data = {"status": "error", "message": f"Server internal error: {e}"}
                    print(f"Server: Error processing request from {addr}: {e}")
                    self.log_event(f"Error processing request from {addr}: {e}")

                # --- ALWAYS SEND A RESPONSE ---
                response_json = json.dumps(response_data)
                conn.sendall(response_json.encode('utf-8'))
                print(f"Server: Sent response to {addr}: {response_json}")
                self.log_event(f"Sent response to {addr}: {response_json}")

        except socket.error as e:
            print(f"Server: Socket error with client {addr}: {e}")
            self.log_event(f"Socket error with client {addr}: {e}")
        except Exception as e:
            print(f"Server: Unexpected error in handle_client for {addr}: {e}")
            self.log_event(f"Unexpected error in handle_client for {addr}: {e}")
        finally:
            print(f"Server: Connection with {addr} closed.")
            self.log_event(f"Connection with {addr} closed.")
            conn.close()
            # Clean up user session if it was active and the handler is exiting
            if current_user and session_id:
                # Check if this session is still active and remove it
                if self.logged_in_users.get(current_user, {}).get("session_id") == session_id:
                    self.logged_in_users.pop(current_user, None)
                    self.log_event(f"User {current_user} session {session_id} removed on handler termination.")

    def run(self):
        print("Server run() method started.")
        while True:
            try:
                conn, addr = self.server_socket.accept()
                print(f"Server: Accepted connection from {addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_handler.start()
            except Exception as e:
                print(f"Server: Error accepting client connection: {e}")
                self.log_event(f"Error accepting client connection: {e}")
                break # Exit loop on critical error

# Main execution block
if __name__ == "__main__":
    print("Main execution block entered.")
    try:
        server = FileServer()
        server.run()
    except Exception as e:
        print(f"An unexpected error occurred in main execution: {e}")

