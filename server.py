import socket
import threading
import json
import time
import random
from collections import defaultdict, deque

class FileResource:
    def __init__(self):
        self.condition = threading.Condition()
        self.readers = 0
        self.writer_active = False
        self.pending_requests = deque()

    def acquire_read(self, username, session_id):
        with self.condition:
            print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) attempting READ on file. Readers: {self.readers}, Writer Active: {self.writer_active}, Queue: {len(self.pending_requests)}")
            while self.writer_active or (self.pending_requests and self.pending_requests[0] != (username, 'read', session_id)):
                print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) READ waiting. Writer: {self.writer_active}, Readers: {self.readers}, Next in queue: {self.pending_requests[0] if self.pending_requests else 'None'}")
                self.condition.wait()
            self.readers += 1
            print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) READ acquired. Current readers: {self.readers}")
            return True

    def release_read(self):
        with self.condition:
            print(f"[DEBUG:Resource] Releasing READ lock. Current readers before: {self.readers}")
            self.readers -= 1
            if self.readers == 0:
                print("[DEBUG:Resource] Last reader leaving, notifying all waiters.")
                self.condition.notify_all()
            print(f"[DEBUG:Resource] READ released. Current readers: {self.readers}")

    def acquire_write(self, username, session_id):
        with self.condition:
            print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) attempting WRITE on file. Readers: {self.readers}, Writer Active: {self.writer_active}, Queue: {len(self.pending_requests)}")
            while self.readers > 0 or self.writer_active or (self.pending_requests and self.pending_requests[0] != (username, 'write', session_id)):
                print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) WRITE waiting. Readers: {self.readers}, Writer: {self.writer_active}, Next in queue: {self.pending_requests[0] if self.pending_requests else 'None'}")
                self.condition.wait()
            self.writer_active = True
            print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) WRITE acquired.")
            return True

    def release_write(self):
        with self.condition:
            print("[DEBUG:Resource] Releasing WRITE lock.")
            self.writer_active = False
            print("[DEBUG:Resource] Writer left, notifying all waiters.")
            self.condition.notify_all()


class FileServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            print(f"[SERVER] Socket bound to {self.host}:{self.port}")
        except socket.error as e:
            print(f"[SERVER_ERROR] Error binding socket: {e}")
            raise

        self.server_socket.listen(5)
        print(f"[SERVER] Server listening on {self.host}:{self.port}")

        self.users = {
            "user1": {"password": "password1", "roles": ["admin"]},
            "user2": {"password": "password2", "roles": ["user"]},
            "user3": {"password": "password3", "roles": ["guest"]}
        }
        self.files = {
            "fileA": {"owner": "user1", "permissions": {"read": ["admin", "user", "guest"], "write": ["admin", "user"]}},
            "fileB": {"owner": "user2", "permissions": {"read": ["admin", "user"], "write": ["admin"]}},
            "fileC": {"owner": "user1", "permissions": {"read": ["admin", "user"], "write": ["admin", "user"]}}
        }
        self.logged_in_users = {}
        self.log_file = "server_log.txt"
        self.log_lock = threading.Lock()

        self.file_resources = {file_name: FileResource() for file_name in self.files}

        self.file_access_history = {file_name: deque(maxlen=10) for file_name in self.files}

        self.init_log()
        print("[SERVER] FileServer initialization complete.")

    def init_log(self):
        with self.log_lock:
            with open(self.log_file, "a") as f:
                f.write(f"[{time.ctime()}] Server started at {self.host}:{self.port}\n")
        print(f"[{time.ctime()}] Server started at {self.host}:{self.port}")

    def log_event(self, event):
        with self.log_lock:
            with open(self.log_file, "a") as f:
                f.write(f"[{time.ctime()}] {event}\n")
        print(f"[{time.ctime()}] {event}")

    def authenticate_user(self, username, password, addr):
        self.log_event(f"Attempting to authenticate user '{username}' from {addr}")
        if username in self.users and self.users[username]["password"] == password:
            if username in self.logged_in_users:
                self.log_event(f"User {username} attempted login from {addr} but already logged in.")
                return {"status": "error", "message": "User already logged in."}

            session_id = f"{username}_{int(time.time())}_{random.randint(1000, 9999)}"
            self.logged_in_users[username] = {
                "session_id": session_id,
                "role": self.users[username]["roles"][0],
                "addr": addr
            }
            self.log_event(f"User {username} successfully logged in from {addr} with session {session_id}.")
            return {"status": "success", "message": "Login successful.", "session_id": session_id}
        else:
            self.log_event(f"Failed login attempt for '{username}' from {addr}.")
            return {"status": "denied", "message": "Invalid username or password."}

    def logout_user(self, username, session_id):
        self.log_event(f"Attempting to log out user '{username}' with session '{session_id}'")
        if username in self.logged_in_users and self.logged_in_users[username]["session_id"] == session_id:
            del self.logged_in_users[username]
            self.log_event(f"User {username} successfully logged out with session {session_id}.")
            return {"status": "success", "message": "Logout successful."}
        else:
            self.log_event(f"Failed logout attempt for '{username}' with invalid session {session_id}.")
            return {"status": "error", "message": "User not logged in or invalid session."}

    def check_file_access_permissions(self, username, user_role, filename, access_type):
        self.log_event(f"Checking {access_type} access permissions for '{username}' ({user_role}) on '{filename}'")
        if filename not in self.files:
            self.log_event(f"File '{filename}' not found during permission check.")
            return {"status": "denied", "message": f"File '{filename}' not found."}

        file_info = self.files[filename]
        required_permissions = file_info["permissions"].get(access_type, [])

        if user_role in required_permissions:
            self.log_event(f"Access {access_type} permissions granted to '{username}' for '{filename}'.")
            return {"status": "granted", "message": f"{access_type.capitalize()} permissions granted for {filename}."}
        else:
            self.log_event(f"Access {access_type} permissions denied to '{username}' for '{filename}'. Role '{user_role}' not in required permissions: {required_permissions}.")
            return {"status": "denied", "message": f"{access_type.capitalize()} permissions denied for {filename}. Insufficient permissions."}

    def record_file_access(self, filename, username, access_type, status):
        if filename in self.file_access_history:
            self.file_access_history[filename].append((time.time(), username, access_type, status))
            self.log_event(f"File access recorded: {filename} by {username} ({access_type}, {status}). History length: {len(self.file_access_history[filename])}")
        else:
            self.log_event(f"Attempted to record access for unknown file: {filename}")

    def request_file_access(self, username, user_role, filename, access_type, session_id):
        perm_check_result = self.check_file_access_permissions(username, user_role, filename, access_type)
        if perm_check_result["status"] == "denied":
            self.record_file_access(filename, username, access_type, "denied_permission")
            return perm_check_result

        file_resource = self.file_resources.get(filename)
        if not file_resource:
            self.log_event(f"Attempted to access non-existent file resource: {filename}")
            self.record_file_access(filename, username, access_type, "denied_not_found")
            return {"status": "error", "message": f"File '{filename}' resource not found on server."}

        with file_resource.condition:
            file_resource.pending_requests.append((username, access_type, session_id))
            self.log_event(f"Request for {filename} by {username} ({access_type}) added to queue. Current queue length: {len(file_resource.pending_requests)}")

        acquired = False
        try:
            if access_type == "read":
                acquired = file_resource.acquire_read(username, session_id)
            elif access_type == "write":
                acquired = file_resource.acquire_write(username, session_id)
            
            if acquired:
                with file_resource.condition:
                    if file_resource.pending_requests and file_resource.pending_requests[0] == (username, access_type, session_id):
                        file_resource.pending_requests.popleft()
                        self.log_event(f"Request for {filename} by {username} ({access_type}) removed from queue. New queue length: {len(file_resource.pending_requests)}")
                
                self.record_file_access(filename, username, access_type, "granted")
                self.log_event(f"Access {access_type} granted to {username} for {filename} (from queue).")
                return {"status": "granted", "message": f"{access_type.capitalize()} access granted for {filename}."}
            else:
                self.record_file_access(filename, username, access_type, "denied_lock_fail")
                return {"status": "denied", "message": f"{access_type.capitalize()} access denied due to lock contention for {filename}."}
        except Exception as e:
            self.log_event(f"Error acquiring lock for {filename} by {username}: {e}")
            self.record_file_access(filename, username, access_type, "error_lock_acquire")
            return {"status": "error", "message": f"Server error acquiring lock: {e}"}

    def release_file_access(self, username, filename, access_type, session_id):
        file_resource = self.file_resources.get(filename)
        if not file_resource:
            self.log_event(f"Attempted to release non-existent file resource: {filename}")
            return {"status": "error", "message": f"File '{filename}' resource not found on server."}

        try:
            if access_type == "read":
                file_resource.release_read()
            elif access_type == "write":
                file_resource.release_write()
            
            self.record_file_access(filename, username, access_type, "released")
            self.log_event(f"Access {access_type} released by {username} for {filename}.")
            return {"status": "success", "message": f"Access to {filename} released by {username}."}
        except Exception as e:
            self.log_event(f"Error releasing lock for {filename} by {username}: {e}")
            self.record_file_access(filename, username, access_type, "error_lock_release")
            return {"status": "error", "message": f"Server error releasing lock: {e}"}

    def handle_client(self, conn, addr):
        current_user = None
        session_id = None
        user_role = None
        self.log_event(f"New connection from {addr}")

        try:
            while True:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    self.log_event(f"Client {addr} disconnected gracefully.")
                    if current_user and session_id and \
                       self.logged_in_users.get(current_user, {}).get("session_id") == session_id:
                        del self.logged_in_users[current_user]
                        self.log_event(f"User {current_user} session {session_id} removed on disconnect.")
                    break

                request = {}
                response_data = {"status": "error", "message": "Invalid request format."}

                try:
                    request = json.loads(data)
                    self.log_event(f"Received request from {addr}: {request}")

                    action = request.get("action")
                    
                    if action == "login":
                        username = request.get("username")
                        password = request.get("password")
                        response_data = self.authenticate_user(username, password, addr)
                        if response_data.get("status") == "success":
                            current_user = username
                            session_id = response_data.get("session_id")
                            user_role = self.logged_in_users[current_user]["role"]
                            self.log_event(f"Handler for {addr}: Authenticated user {current_user} with session {session_id[-4:]}.")
                        conn.sendall(json.dumps(response_data).encode('utf-8'))
                        self.log_event(f"Sent login response to {addr}: {response_data}")
                        continue

                    if not current_user or not session_id or not user_role:
                        response_data = {"status": "denied", "message": "Authentication required. Please log in first."}
                        conn.sendall(json.dumps(response_data).encode('utf-8'))
                        self.log_event(f"Denied unauthenticated request from {addr} for action '{action}'. Not logged in.")
                        continue

                    if current_user not in self.logged_in_users or \
                       self.logged_in_users[current_user]["session_id"] != session_id:
                        
                        if current_user in self.logged_in_users:
                            del self.logged_in_users[current_user]
                            self.log_event(f"User {current_user} session {session_id[-4:]} invalidated due to new login elsewhere or server restart. Cleaning up.")

                        current_user = None
                        session_id = None
                        user_role = None
                        response_data = {"status": "denied", "message": "Invalid or expired session. Please log in again."}
                        conn.sendall(json.dumps(response_data).encode('utf-8'))
                        self.log_event(f"Denied request from {addr} for action '{action}'. Session {session_id[-4:]} is invalid/expired for user {current_user}.")
                        continue

                    if action == "request_access":
                        filename = request.get("filename")
                        access_type = request.get("access_type")
                        response_data = self.request_file_access(current_user, user_role, filename, access_type, session_id)

                    elif action == "release_access":
                        filename = request.get("filename")
                        access_type = request.get("access_type")
                        response_data = self.release_file_access(current_user, filename, access_type, session_id)

                    elif action == "logout":
                        response_data = self.logout_user(current_user, session_id)
                        if response_data.get("status") == "success":
                            current_user = None
                            session_id = None
                            user_role = None
                    else:
                        response_data = {"status": "error", "message": "Unknown action."}

                except json.JSONDecodeError as e:
                    response_data = {"status": "error", "message": f"JSON decoding error: {e}"}
                    self.log_event(f"JSON decode error from {addr}: {e}, Raw data: '{data}'")
                except Exception as e:
                    response_data = {"status": "error", "message": f"Server internal error: {e}"}
                    self.log_event(f"Error processing request from {addr}: {e}")

                response_json = json.dumps(response_data)
                conn.sendall(response_json.encode('utf-8'))
                self.log_event(f"Sent response to {addr}: {response_json}")

        except socket.error as e:
            self.log_event(f"Socket error with client {addr}: {e}")
        except Exception as e:
            self.log_event(f"Unexpected error in handle_client for {addr}: {e}")
        finally:
            self.log_event(f"Connection with {addr} closed.")
            conn.close()
            if current_user and session_id and \
               self.logged_in_users.get(current_user, {}).get("session_id") == session_id:
                del self.logged_in_users[current_user]
                self.log_event(f"User {current_user} session {session_id[-4:]} removed on handler termination.")

    def run(self):
        self.log_event("Server run() method started. Waiting for connections...")
        while True:
            try:
                conn, addr = self.server_socket.accept()
                self.log_event(f"Accepted connection from {addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_handler.start()
            except Exception as e:
                self.log_event(f"Error accepting client connection: {e}")
                break

if __name__ == "__main__":
    print("[MAIN] Main execution block entered.")
    try:
        server = FileServer()
        server.run()
    except Exception as e:
        print(f"[MAIN_ERROR] An unexpected error occurred in main execution: {e}")
