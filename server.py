import socket
import threading
import json
import time
from collections import defaultdict, deque

class FileServer:
# Classe responsável por controlar o acesso concorrente aos arquivos usando sockets TCP.
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Estruturas para controle de acesso
        self.file_locks = defaultdict(threading.Lock)
        self.file_queues = defaultdict(deque)
        self.client_files = defaultdict(set)
        
        # Log de operações
        self.log_lock = threading.Lock()
        self.log_file = "server_log.txt"
        self._init_log()

    def _init_log(self):
        with open(self.log_file, 'w') as f:
            f.write("=== SERVER LOG ===\n")
            f.write(f"Server started at {time.ctime()}\n\n")

    def _log(self, message):
        with self.log_lock:
            with open(self.log_file, 'a') as f:
                f.write(f"[{time.ctime()}] {message}\n")

    def handle_client(self, client_socket, client_address):
    # Lida com cada cliente conectado, processando suas requisições enquanto durar a conexão.
        try:
            self._log(f"New connection from {client_address}")
            while True:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                try:
                    request = json.loads(data)
                    self._log(f"Request from {client_address}: {request}")
                    
                    response = self.process_request(request, client_address)
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    self._log(f"Response to {client_address}: {response}")
                    
                except json.JSONDecodeError:
                    response = {"status": "error", "message": "Invalid JSON format"}
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    
        except ConnectionResetError:
            self._log(f"Connection reset by {client_address}")
        finally:
            client_socket.close()
            self._log(f"Connection closed with {client_address}")

    def process_request(self, request, client_address):
        action = request.get("action")
        filename = request.get("filename")
        client_id = request.get("client_id")
        
        if action == "read":
            return self.handle_read(filename, client_id)
        elif action == "write":
            return self.handle_write(filename, client_id)
        elif action == "release":
            return self.handle_release(filename, client_id)
        else:
            return {"status": "error", "message": "Invalid action"}

    def handle_read(self, filename, client_id):
        with self.file_locks[filename]:
            if filename not in self.file_queues or not self.file_queues[filename]:
                self.client_files[client_id].add(filename)
                return {"status": "granted", "message": f"Read access granted for {filename}"}
            
            self.file_queues[filename].append(("read", client_id))
            return {"status": "queued", "message": f"Read request queued for {filename}"}

    def handle_write(self, filename, client_id):
        with self.file_locks[filename]:
            if filename not in self.file_queues or not self.file_queues[filename]:
                if not self.client_files:  # Nenhum cliente acessando o arquivo
                    self.client_files[client_id].add(filename)
                    return {"status": "granted", "message": f"Write access granted for {filename}"}
                
            self.file_queues[filename].append(("write", client_id))
            return {"status": "queued", "message": f"Write request queued for {filename}"}

    def handle_release(self, filename, client_id):
        with self.file_locks[filename]:
            if filename in self.client_files[client_id]:
                self.client_files[client_id].remove(filename)
                if not self.client_files[client_id]:
                    del self.client_files[client_id]
                
                self.process_queue(filename)
                return {"status": "released", "message": f"Released access to {filename}"}
            return {"status": "error", "message": f"No access to release for {filename}"}

    def process_queue(self, filename):
        if filename in self.file_queues and self.file_queues[filename]:
            next_action, next_client = self.file_queues[filename].popleft()
            self.client_files[next_client].add(filename)
            return {"status": "granted", "client_id": next_client, "action": next_action}
        return None

    def start(self):
    # Inicializa o servidor e escuta por conexões simultâneas, criando uma thread para cada novo cliente.
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self._log(f"Server listening on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.start()
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    server = FileServer()
    server.start()
