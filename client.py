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
        try:
            self.socket.connect((self.server_host, self.server_port))
        except ConnectionRefusedError:
            raise
        except Exception as e:
            raise

    def send_request(self, request_payload):
        request_json = json.dumps(request_payload)
        try:
            self.socket.sendall(request_json.encode('utf-8'))
            response_data = self.socket.recv(1024).decode('utf-8')
            return json.loads(response_data)
        except socket.error as e:
            return {"status": "error", "message": f"Socket error: {e}"}
        except json.JSONDecodeError as e:
            return {"status": "error", "message": f"JSON decode error: {e}"}
        except Exception as e:
            return {"status": "error", "message": f"Unexpected error: {e}"}

    def request_login(self):
        if not self.username or not self.password:
            return {"status": "error", "message": "No login credentials."}

        request_payload = {
            "action": "login",
            "username": self.username,
            "password": self.password
        }
        response = self.send_request(request_payload)
        if response.get("status") == "success":
            self.session_id = response.get("session_id")
        return response

    def request_access(self, filename, access_type):
        request_payload = {
            "action": "request_access",
            "filename": filename,
            "access_type": access_type,
            "client_id": self.client_id,
            "session_id": self.session_id
        }
        return self.send_request(request_payload)

    def release_access(self, filename, access_type):
        request_payload = {
            "action": "release_access",
            "filename": filename,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "access_type": access_type
        }
        return self.send_request(request_payload)

    def request_logout(self):
        if not self.username or not self.session_id:
            return {"status": "error", "message": "Not logged in."}

        request_payload = {
            "action": "logout",
            "username": self.username,
            "session_id": self.session_id
        }
        response = self.send_request(request_payload)
        if response.get("status") == "success":
            self.session_id = None
        return response

    def simulate_work(self, max_operations=5):
        try:
            self.connect()

            login_resp = self.request_login()
            if login_resp.get("status") != "success":
                return

            for i in range(max_operations):
                action = random.choice(["read", "write"])
                file_name = random.choice(self.file_list)

                response = self.request_access(file_name, action)

                if response and response.get('status') == 'granted':
                    work_time = random.randint(1, 5)
                    time.sleep(work_time)

                    release_resp = self.release_access(file_name, action)
                else:
                    pass

                time.sleep(random.uniform(0.5, 2.0))

            logout_resp = self.request_logout()

        except ConnectionRefusedError:
            pass
        except Exception as e:
            pass
        finally:
            self.disconnect()

    def disconnect(self):
        if self.socket:
            self.socket.close()
            self.socket = None

if __name__ == "__main__":
    FILES = ["fileA", "fileB", "fileC"]

    container_client_id = os.getenv('HOSTNAME', 'default_client')

    username_map = {
        'file-client-1': 'user1',
        'file-client-2': 'user2',
        'file-client-3': 'user3',
        'default_client': 'user1'
    }
    password_map = {
        'file-client-1': 'password1',
        'file-client-2': 'password2',
        'file-client-3': 'password3',
        'default_client': 'password1'
    }

    client_user = username_map.get(container_client_id, 'user1')
    client_pass = password_map.get(container_client_id, 'password1')

    client = FileClient(
        client_id=container_client_id,
        file_list=FILES,
        username=client_user,
        password=client_pass,
        server_host='file-server'
    )

    client.simulate_work(max_operations=5)
