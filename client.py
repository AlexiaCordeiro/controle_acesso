import socket
import json
import random
import time
import threading

class FileClient:
    def __init__(self, client_id, server_host='localhost', server_port=5000):
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected_files = set()
        
    def connect(self):
        self.socket.connect((self.server_host, self.server_port))
        
    def send_request(self, action, filename):
        request = {
            "action": action,
            "filename": filename,
            "client_id": self.client_id
        }
        self.socket.send(json.dumps(request).encode('utf-8'))
        response = self.socket.recv(1024).decode('utf-8')
        return json.loads(response)
    
    def simulate_work(self, filename, action, work_time=3):
        print(f"Client {self.client_id} requesting {action} access to {filename}")
        response = self.send_request(action, filename)
        print(f"Client {self.client_id} received: {response}")
        
        if response.get("status") == "granted":
            self.connected_files.add(filename)
            print(f"Client {self.client_id} working on {filename} ({action}) for {work_time} seconds")
            time.sleep(work_time)
            
            # Liberar o arquivo após o trabalho
            release_resp = self.send_request("release", filename)
            print(f"Client {self.client_id} released {filename}: {release_resp}")
            self.connected_files.remove(filename)
        else:
            print(f"Client {self.client_id} waiting for access to {filename}")
    
    def close(self):
        for filename in list(self.connected_files):
            self.send_request("release", filename)
        self.socket.close()

def simulate_client(client_id, files, actions, max_operations=5):
    client = FileClient(client_id)
    client.connect()
    
    for _ in range(max_operations):
        filename = random.choice(files)
        action = random.choice(actions)
        client.simulate_work(filename, action, random.randint(1, 5))
        time.sleep(random.uniform(0.5, 2.0))
    
    client.close()

if __name__ == "__main__":
    # Configuração da simulação
    FILES = ["file1.txt", "file2.txt", "file3.txt"]
    ACTIONS = ["read", "write"]
    CLIENTS = 5  # Número de clientes simultâneos
    
    threads = []
    for i in range(CLIENTS):
        thread = threading.Thread(
            target=simulate_client,
            args=(f"client_{i+1}", FILES, ACTIONS)
        )
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
