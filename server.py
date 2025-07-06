import socket
import threading
import json
import time
import random
from collections import defaultdict, deque

class FileResource:
    """
    Representa um recurso de arquivo gerenciado pelo servidor, controlando o acesso de leitura e escrita.

    Implementa um mecanismo de leitores-escritores com uma fila de requisições pendentes
    para garantir a exclusão mútua para escrita e permitir múltiplos leitores simultâneos.
    """
    def __init__(self):
        """
        Inicializa uma nova instância de FileResource.

        Configura uma condição de threading para sincronização, contadores para leitores e escritores,
        e uma deque para gerenciar requisições pendentes.
        """
        self.condition = threading.Condition()
        self.readers = 0
        self.writer_active = False
        self.pending_requests = deque()

    def acquire_read(self, username, session_id):
        """
        Adquire um bloqueio de leitura para o recurso de arquivo.

        O cliente esperará se houver um escritor ativo ou se houver requisições pendentes
        que não sejam a sua própria requisição de leitura (para garantir a ordem da fila).

        Args:
            username (str): O nome de usuário que está solicitando o acesso de leitura.
            session_id (str): O ID da sessão do usuário.

        Returns:
            bool: True se o bloqueio de leitura foi adquirido com sucesso.
        """
        with self.condition:
            print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) tentando LEITURA no arquivo. Leitores: {self.readers}, Escritor Ativo: {self.writer_active}, Fila: {len(self.pending_requests)}")
            # Espera se houver um escritor ativo OU se houver requisições na fila e a primeira não for esta requisição de leitura
            while self.writer_active or (self.pending_requests and self.pending_requests[0] != (username, 'read', session_id)):
                print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) LEITURA esperando. Escritor: {self.writer_active}, Leitores: {self.readers}, Próximo na fila: {self.pending_requests[0] if self.pending_requests else 'None'}")
                self.condition.wait()
            self.readers += 1
            print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) LEITURA adquirida. Leitores atuais: {self.readers}")
            return True

    def release_read(self):
        """
        Libera um bloqueio de leitura para o recurso de arquivo.

        Se este for o último leitor a liberar o bloqueio, notifica todas as threads em espera.
        """
        with self.condition:
            print(f"[DEBUG:Resource] Liberando bloqueio de LEITURA. Leitores atuais antes: {self.readers}")
            self.readers -= 1
            if self.readers == 0:
                print("[DEBUG:Resource] Último leitor saindo, notificando todos os que esperam.")
                self.condition.notify_all()
            print(f"[DEBUG:Resource] LEITURA liberada. Leitores atuais: {self.readers}")

    def acquire_write(self, username, session_id):
        """
        Adquire um bloqueio de escrita para o recurso de arquivo.

        O cliente esperará se houver leitores ativos, um escritor ativo, ou se houver
        requisições pendentes que não sejam a sua própria requisição de escrita.

        Args:
            username (str): O nome de usuário que está solicitando o acesso de escrita.
            session_id (str): O ID da sessão do usuário.

        Returns:
            bool: True se o bloqueio de escrita foi adquirido com sucesso.
        """
        with self.condition:
            print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) tentando ESCRITA no arquivo. Leitores: {self.readers}, Escritor Ativo: {self.writer_active}, Fila: {len(self.pending_requests)}")
            # Espera se houver leitores, um escritor ativo OU se houver requisições na fila e a primeira não for esta requisição de escrita
            while self.readers > 0 or self.writer_active or (self.pending_requests and self.pending_requests[0] != (username, 'write', session_id)):
                print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) ESCRITA esperando. Leitores: {self.readers}, Escritor: {self.writer_active}, Próximo na fila: {self.pending_requests[0] if self.pending_requests else 'None'}")
                self.condition.wait()
            self.writer_active = True
            print(f"[DEBUG:Resource] {username} (Session {session_id[-4:]}) ESCRITA adquirida.")
            return True

    def release_write(self):
        """
        Libera um bloqueio de escrita para o recurso de arquivo.

        Notifica todas as threads em espera, pois o escritor deixou o recurso.
        """
        with self.condition:
            print("[DEBUG:Resource] Liberando bloqueio de ESCRITA.")
            self.writer_active = False
            print("[DEBUG:Resource] Escritor saiu, notificando todos os que esperam.")
            self.condition.notify_all()


class FileServer:
    """
    Implementa um servidor de arquivos que gerencia o acesso a arquivos para múltiplos clientes.

    O servidor lida com autenticação de usuários, controle de acesso baseado em permissões
    e gerenciamento de concorrência de arquivos usando o padrão leitores-escritores.
    Ele também mantém um log de eventos do servidor e histórico de acesso a arquivos.
    """
    def __init__(self, host='0.0.0.0', port=5000):
        """
        Inicializa o FileServer, configurando o socket do servidor, usuários, arquivos e recursos.

        Args:
            host (str, opcional): O endereço IP ou hostname no qual o servidor irá escutar.
                                  Padrão para '0.0.0.0' (todos os endereços disponíveis).
            port (int, opcional): A porta na qual o servidor irá escutar. Padrão para 5000.

        Raises:
            socket.error: Se houver um erro ao vincular o socket.
        """
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            print(f"[SERVER] Socket vinculado a {self.host}:{self.port}")
        except socket.error as e:
            print(f"[SERVER_ERROR] Erro ao vincular o socket: {e}")
            raise

        self.server_socket.listen(5)
        print(f"[SERVER] Servidor escutando em {self.host}:{self.port}")

        # Dados de usuários e arquivos
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
        self.logged_in_users = {} # Armazena usuários logados e seus detalhes de sessão
        self.log_file = "server_log.txt"
        self.log_lock = threading.Lock() # Bloqueio para garantir acesso seguro ao arquivo de log

        # Inicializa um objeto FileResource para cada arquivo para gerenciar o acesso concorrente
        self.file_resources = {file_name: FileResource() for file_name in self.files}

        # Histórico de acesso a arquivos (limitado aos últimos 10 eventos por arquivo)
        self.file_access_history = {file_name: deque(maxlen=10) for file_name in self.files}

        self.init_log()
        print("[SERVER] Inicialização do FileServer completa.")

    def init_log(self):
        """
        Inicializa o arquivo de log do servidor, registrando a hora de início do servidor.
        """
        with self.log_lock:
            with open(self.log_file, "a") as f:
                f.write(f"[{time.ctime()}] Servidor iniciado em {self.host}:{self.port}\n")
        print(f"[{time.ctime()}] Servidor iniciado em {self.host}:{self.port}")

    def log_event(self, event):
        """
        Registra um evento no arquivo de log do servidor com um timestamp.

        Args:
            event (str): A mensagem do evento a ser registrada.
        """
        with self.log_lock:
            with open(self.log_file, "a") as f:
                f.write(f"[{time.ctime()}] {event}\n")
        print(f"[{time.ctime()}] {event}")

    def authenticate_user(self, username, password, addr):
        """
        Autentica um usuário com base no nome de usuário e senha fornecidos.

        Se a autenticação for bem-sucedida e o usuário não estiver logado,
        uma nova sessão é criada e registrada.

        Args:
            username (str): O nome de usuário a ser autenticado.
            password (str): A senha a ser verificada.
            addr (tuple): O endereço (IP, porta) do cliente.

        Returns:
            dict: Um dicionário contendo o status ('success', 'denied', 'error') e uma mensagem.
                  Em caso de sucesso, inclui o 'session_id'.
        """
        self.log_event(f"Tentando autenticar usuário '{username}' de {addr}")
        if username in self.users and self.users[username]["password"] == password:
            if username in self.logged_in_users:
                self.log_event(f"Usuário {username} tentou login de {addr} mas já está logado.")
                return {"status": "error", "message": "Usuário já logado."}

            session_id = f"{username}_{int(time.time())}_{random.randint(1000, 9999)}"
            self.logged_in_users[username] = {
                "session_id": session_id,
                "role": self.users[username]["roles"][0], # Assume a primeira role como a principal
                "addr": addr
            }
            self.log_event(f"Usuário {username} logado com sucesso de {addr} com sessão {session_id}.")
            return {"status": "success", "message": "Login bem-sucedido.", "session_id": session_id}
        else:
            self.log_event(f"Tentativa de login falhou para '{username}' de {addr}.")
            return {"status": "denied", "message": "Nome de usuário ou senha inválidos."}

    def logout_user(self, username, session_id):
        """
        Desloga um usuário do servidor, encerrando sua sessão.

        Args:
            username (str): O nome de usuário a ser deslogado.
            session_id (str): O ID da sessão do usuário.

        Returns:
            dict: Um dicionário contendo o status ('success', 'error') e uma mensagem.
        """
        self.log_event(f"Tentando fazer logout do usuário '{username}' com sessão '{session_id}'")
        if username in self.logged_in_users and self.logged_in_users[username]["session_id"] == session_id:
            del self.logged_in_users[username]
            self.log_event(f"Usuário {username} deslogado com sucesso com sessão {session_id}.")
            return {"status": "success", "message": "Logout bem-sucedido."}
        else:
            self.log_event(f"Tentativa de logout falhou para '{username}' com sessão inválida {session_id}.")
            return {"status": "error", "message": "Usuário não logado ou sessão inválida."}

    def check_file_access_permissions(self, username, user_role, filename, access_type):
        """
        Verifica se um usuário tem permissão para realizar um tipo de acesso (leitura/escrita) em um arquivo.

        Args:
            username (str): O nome de usuário que solicita o acesso.
            user_role (str): A função do usuário.
            filename (str): O nome do arquivo.
            access_type (str): O tipo de acesso solicitado ('read' ou 'write').

        Returns:
            dict: Um dicionário contendo o status ('granted', 'denied') e uma mensagem.
        """
        self.log_event(f"Verificando permissões de acesso de {access_type} para '{username}' ({user_role}) em '{filename}'")
        if filename not in self.files:
            self.log_event(f"Arquivo '{filename}' não encontrado durante a verificação de permissão.")
            return {"status": "denied", "message": f"Arquivo '{filename}' não encontrado."}

        file_info = self.files[filename]
        required_permissions = file_info["permissions"].get(access_type, [])

        if user_role in required_permissions:
            self.log_event(f"Permissões de acesso de {access_type} concedidas a '{username}' para '{filename}'.")
            return {"status": "granted", "message": f"{access_type.capitalize()} permissões concedidas para {filename}."}
        else:
            self.log_event(f"Permissões de acesso de {access_type} negadas a '{username}' para '{filename}'. Função '{user_role}' não está nas permissões necessárias: {required_permissions}.")
            return {"status": "denied", "message": f"{access_type.capitalize()} permissões negadas para {filename}. Permissões insuficientes."}

    def record_file_access(self, filename, username, access_type, status):
        """
        Registra um evento de acesso a arquivo no histórico de acesso do arquivo.

        Args:
            filename (str): O nome do arquivo acessado.
            username (str): O nome de usuário que acessou o arquivo.
            access_type (str): O tipo de acesso (e.g., 'read', 'write').
            status (str): O status do acesso (e.g., 'granted', 'denied_permission', 'released').
        """
        if filename in self.file_access_history:
            self.file_access_history[filename].append((time.time(), username, access_type, status))
            self.log_event(f"Acesso ao arquivo registrado: {filename} por {username} ({access_type}, {status}). Tamanho do histórico: {len(self.file_access_history[filename])}")
        else:
            self.log_event(f"Tentativa de registrar acesso para arquivo desconhecido: {filename}")

    def request_file_access(self, username, user_role, filename, access_type, session_id):
        """
        Gerencia a solicitação de acesso de um cliente a um arquivo, incluindo verificação de permissões
        e aquisição de bloqueios de recurso.

        Args:
            username (str): O nome de usuário que solicita o acesso.
            user_role (str): A função do usuário.
            filename (str): O nome do arquivo.
            access_type (str): O tipo de acesso solicitado ('read' ou 'write').
            session_id (str): O ID da sessão do usuário.

        Returns:
            dict: Um dicionário contendo o status ('granted', 'denied', 'error') e uma mensagem.
        """
        perm_check_result = self.check_file_access_permissions(username, user_role, filename, access_type)
        if perm_check_result["status"] == "denied":
            self.record_file_access(filename, username, access_type, "denied_permission")
            return perm_check_result

        file_resource = self.file_resources.get(filename)
        if not file_resource:
            self.log_event(f"Tentativa de acessar recurso de arquivo inexistente: {filename}")
            self.record_file_access(filename, username, access_type, "denied_not_found")
            return {"status": "error", "message": f"Recurso do arquivo '{filename}' não encontrado no servidor."}

        with file_resource.condition:
            file_resource.pending_requests.append((username, access_type, session_id))
            self.log_event(f"Requisição para {filename} por {username} ({access_type}) adicionada à fila. Tamanho atual da fila: {len(file_resource.pending_requests)}")

        acquired = False
        try:
            if access_type == "read":
                acquired = file_resource.acquire_read(username, session_id)
            elif access_type == "write":
                acquired = file_resource.acquire_write(username, session_id)
            
            if acquired:
                with file_resource.condition:
                    # Remove a requisição da fila apenas se for a primeira e corresponder
                    if file_resource.pending_requests and file_resource.pending_requests[0] == (username, access_type, session_id):
                        file_resource.pending_requests.popleft()
                        self.log_event(f"Requisição para {filename} por {username} ({access_type}) removida da fila. Novo tamanho da fila: {len(file_resource.pending_requests)}")
                
                self.record_file_access(filename, username, access_type, "granted")
                self.log_event(f"Acesso de {access_type} concedido a {username} para {filename} (da fila).")
                return {"status": "granted", "message": f"Acesso de {access_type.capitalize()} concedido para {filename}."}
            else:
                self.record_file_access(filename, username, access_type, "denied_lock_fail")
                return {"status": "denied", "message": f"Acesso de {access_type.capitalize()} negado devido a contenção de bloqueio para {filename}."}
        except Exception as e:
            self.log_event(f"Erro ao adquirir bloqueio para {filename} por {username}: {e}")
            self.record_file_access(filename, username, access_type, "error_lock_acquire")
            return {"status": "error", "message": f"Erro do servidor ao adquirir bloqueio: {e}"}

    def release_file_access(self, username, filename, access_type, session_id):
        """
        Libera o acesso de um cliente a um arquivo, liberando os bloqueios de recurso.

        Args:
            username (str): O nome de usuário que está liberando o acesso.
            filename (str): O nome do arquivo.
            access_type (str): O tipo de acesso que está sendo liberado ('read' ou 'write').
            session_id (str): O ID da sessão do usuário.

        Returns:
            dict: Um dicionário contendo o status ('success', 'error') e uma mensagem.
        """
        file_resource = self.file_resources.get(filename)
        if not file_resource:
            self.log_event(f"Tentativa de liberar recurso de arquivo inexistente: {filename}")
            return {"status": "error", "message": f"Recurso do arquivo '{filename}' não encontrado no servidor."}

        try:
            if access_type == "read":
                file_resource.release_read()
            elif access_type == "write":
                file_resource.release_write()
            
            self.record_file_access(filename, username, access_type, "released")
            self.log_event(f"Acesso de {access_type} liberado por {username} para {filename}.")
            return {"status": "success", "message": f"Acesso a {filename} liberado por {username}."}
        except Exception as e:
            self.log_event(f"Erro ao liberar bloqueio para {filename} por {username}: {e}")
            self.record_file_access(filename, username, access_type, "error_lock_release")
            return {"status": "error", "message": f"Erro do servidor ao liberar bloqueio: {e}"}

    def handle_client(self, conn, addr):
        """
        Lida com as requisições de um cliente conectado em uma thread separada.

        Processa requisições de login, logout, solicitação de acesso e liberação de acesso a arquivos.
        Mantém o estado de autenticação do cliente durante a conexão.

        Args:
            conn (socket.socket): O objeto socket para a conexão do cliente.
            addr (tuple): O endereço (IP, porta) do cliente.
        """
        current_user = None
        session_id = None
        user_role = None
        self.log_event(f"Nova conexão de {addr}")

        try:
            while True:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    self.log_event(f"Cliente {addr} desconectado graciosamente.")
                    # Se o cliente desconectou e ainda está logado, remove a sessão
                    if current_user and session_id and \
                       self.logged_in_users.get(current_user, {}).get("session_id") == session_id:
                        del self.logged_in_users[current_user]
                        self.log_event(f"Sessão do usuário {current_user} {session_id} removida na desconexão.")
                    break

                request = {}
                response_data = {"status": "error", "message": "Formato de requisição inválido."}

                try:
                    request = json.loads(data)
                    self.log_event(f"Requisição recebida de {addr}: {request}")

                    action = request.get("action")
                    
                    if action == "login":
                        username = request.get("username")
                        password = request.get("password")
                        response_data = self.authenticate_user(username, password, addr)
                        if response_data.get("status") == "success":
                            current_user = username
                            session_id = response_data.get("session_id")
                            user_role = self.logged_in_users[current_user]["role"]
                            self.log_event(f"Handler para {addr}: Usuário autenticado {current_user} com sessão {session_id[-4:]}.")
                        conn.sendall(json.dumps(response_data).encode('utf-8'))
                        self.log_event(f"Resposta de login enviada para {addr}: {response_data}")
                        continue # Continua para a próxima iteração do loop para aguardar mais requisições

                    # Para todas as outras ações, o usuário deve estar autenticado
                    if not current_user or not session_id or not user_role:
                        response_data = {"status": "denied", "message": "Autenticação necessária. Por favor, faça login primeiro."}
                        conn.sendall(json.dumps(response_data).encode('utf-8'))
                        self.log_event(f"Requisição não autenticada negada de {addr} para ação '{action}'. Não logado.")
                        continue

                    # Verifica se a sessão do usuário ainda é válida no servidor
                    if current_user not in self.logged_in_users or \
                       self.logged_in_users[current_user]["session_id"] != session_id:
                        
                        # Se o usuário existe, mas a sessão é diferente (e.g., novo login em outro lugar), limpa a sessão antiga
                        if current_user in self.logged_in_users:
                            del self.logged_in_users[current_user]
                            self.log_event(f"Sessão do usuário {current_user} {session_id[-4:]} invalidada devido a novo login em outro lugar ou reinício do servidor. Limpando.")

                        current_user = None
                        session_id = None
                        user_role = None
                        response_data = {"status": "denied", "message": "Sessão inválida ou expirada. Por favor, faça login novamente."}
                        conn.sendall(json.dumps(response_data).encode('utf-8'))
                        self.log_event(f"Requisição negada de {addr} para ação '{action}'. Sessão {session_id[-4:]} é inválida/expirada para o usuário {current_user}.")
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
                        response_data = {"status": "error", "message": "Ação desconhecida."}

                except json.JSONDecodeError as e:
                    response_data = {"status": "error", "message": f"Erro de decodificação JSON: {e}"}
                    self.log_event(f"Erro de decodificação JSON de {addr}: {e}, Dados brutos: '{data}'")
                except Exception as e:
                    response_data = {"status": "error", "message": f"Erro interno do servidor: {e}"}
                    self.log_event(f"Erro ao processar requisição de {addr}: {e}")

                response_json = json.dumps(response_data)
                conn.sendall(response_json.encode('utf-8'))
                self.log_event(f"Resposta enviada para {addr}: {response_json}")

        except socket.error as e:
            self.log_event(f"Erro de socket com o cliente {addr}: {e}")
        except Exception as e:
            self.log_event(f"Erro inesperado em handle_client para {addr}: {e}")
        finally:
            self.log_event(f"Conexão com {addr} fechada.")
            conn.close()
            # Garante que a sessão seja removida se o handler terminar inesperadamente
            if current_user and session_id and \
               self.logged_in_users.get(current_user, {}).get("session_id") == session_id:
                del self.logged_in_users[current_user]
                self.log_event(f"Sessão do usuário {current_user} {session_id[-4:]} removida na terminação do handler.")

    def run(self):
        """
        Inicia o servidor, escutando por novas conexões de clientes.

        Para cada nova conexão, uma nova thread é criada para lidar com o cliente.
        """
        self.log_event("Método run() do servidor iniciado. Esperando por conexões...")
        while True:
            try:
                conn, addr = self.server_socket.accept()
                self.log_event(f"Conexão aceita de {addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_handler.start()
            except Exception as e:
                self.log_event(f"Erro ao aceitar conexão de cliente: {e}")
                break # Sai do loop se houver um erro grave ao aceitar conexões

if __name__ == "__main__":
    print("[MAIN] Bloco de execução principal iniciado.")
    try:
        server = FileServer()
        server.run()
    except Exception as e:
        print(f"[MAIN_ERROR] Ocorreu um erro inesperado na execução principal: {e}")

