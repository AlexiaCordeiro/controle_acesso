import socket
import json
import random
import time
import os

class FileClient:
    """
    Representa um cliente que interage com um servidor de arquivos para solicitar e liberar acesso a arquivos.

    Este cliente simula operações como login, solicitação de acesso de leitura/escrita a arquivos,
    liberação de acesso e logout. Ele gerencia a comunicação com o servidor via sockets
    e payloads JSON.
    """
    def __init__(self, client_id, file_list, username=None, password=None, server_host='localhost', server_port=5000):
        """
        Inicializa o FileClient com os detalhes do cliente e os parâmetros de conexão do servidor.

        Args:
            client_id (str): Um identificador único para este cliente.
            file_list (list): Uma lista de nomes de arquivos com os quais este cliente pode interagir.
            username (str, opcional): O nome de usuário para autenticação com o servidor. Padrão para None.
            password (str, opcional): A senha para autenticação com o servidor. Padrão para None.
            server_host (str, opcional): O hostname ou endereço IP do servidor de arquivos.
                                         Padrão para 'localhost'. Pode ser sobrescrito pela variável de ambiente 'SERVER_HOST'.
            server_port (int, opcional): A porta na qual o servidor de arquivos está escutando. Padrão para 5000.
        """
        self.client_id = client_id
        self.server_host = os.getenv('SERVER_HOST', server_host)
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected_files = set() # Este atributo não está sendo usado no código fornecido.
        self.file_list = file_list
        self.username = username
        self.password = password
        self.session_id = None

    def connect(self):
        """
        Tenta estabelecer uma conexão de socket com o servidor de arquivos.

        Levanta exceções (ConnectionRefusedError, Exception) se a conexão falhar.
        """
        print(f"[CLIENT {self.client_id}] Tentando conectar a {self.server_host}:{self.server_port}")
        try:
            self.socket.connect((self.server_host, self.server_port))
            print(f"[CLIENT {self.client_id}] Conectado a {self.server_host}:{self.server_port}")
        except ConnectionRefusedError:
            print(f"[CLIENT {self.client_id}_ERROR] Conexão recusada. O servidor está rodando em {self.server_host}:{self.server_port}?")
            raise
        except Exception as e:
            print(f"[CLIENT {self.client_id}_ERROR] Ocorreu um erro durante a conexão: {e}")
            raise

    def send_request(self, request_payload):
        """
        Envia um payload de requisição JSON para o servidor e aguarda uma resposta.

        Args:
            request_payload (dict): Um dicionário representando a requisição a ser enviada ao servidor.

        Returns:
            dict: A resposta do servidor decodificada de JSON, ou um dicionário de erro
                  se ocorrer uma falha na rede ou na decodificação JSON.
        """
        request_json = json.dumps(request_payload)
        print(f"[CLIENT {self.client_id}] Enviando requisição: {request_json}")
        try:
            self.socket.sendall(request_json.encode('utf-8'))
            print(f"[CLIENT {self.client_id}] Dados enviados. Esperando resposta...")

            response_data = self.socket.recv(1024).decode('utf-8')
            print(f"[CLIENT {self.client_id}] Resposta bruta recebida: {response_data}")
            return json.loads(response_data)
        except socket.error as e:
            print(f"[CLIENT {self.client_id}_ERROR] Erro de socket durante a requisição: {e}")
            return {"status": "error", "message": f"Erro de socket: {e}"}
        except json.JSONDecodeError as e:
            print(f"[CLIENT {self.client_id}_ERROR] Erro de decodificação JSON na resposta: {e}, Bruto: '{response_data}'")
            return {"status": "error", "message": f"Erro de decodificação JSON: {e}"}
        except Exception as e:
            print(f"[CLIENT {self.client_id}_ERROR] Erro inesperado em send_request: {e}")
            return {"status": "error", "message": f"Erro inesperado: {e}"}

    def request_login(self):
        """
        Envia uma requisição de login ao servidor usando o nome de usuário e a senha do cliente.

        Se o login for bem-sucedido, armazena o ID da sessão recebido do servidor.

        Returns:
            dict: A resposta do servidor para a requisição de login.
        """
        if not self.username or not self.password:
            print(f"[CLIENT {self.client_id}] Nome de usuário ou senha não configurados para login.")
            return {"status": "error", "message": "Sem credenciais de login."}

        request_payload = {
            "action": "login",
            "username": self.username,
            "password": self.password
        }
        print(f"[CLIENT {self.client_id}] Solicitando login para o usuário: {self.username}")
        response = self.send_request(request_payload)
        if response.get("status") == "success":
            self.session_id = response.get("session_id")
            print(f"[CLIENT {self.client_id}] Login bem-sucedido com ID de sessão: {self.session_id}")
        else:
            print(f"[CLIENT {self.client_id}_ERROR] Login falhou: {response.get('message')}")
        return response

    def request_access(self, filename, access_type):
        """
        Solicita acesso (leitura ou escrita) a um arquivo específico do servidor.

        Requer uma sessão ativa (ou seja, o cliente deve estar logado).

        Args:
            filename (str): O nome do arquivo para o qual solicitar acesso.
            access_type (str): O tipo de acesso solicitado ('read' ou 'write').

        Returns:
            dict: A resposta do servidor para a requisição de acesso.
        """
        if not self.session_id:
            print(f"[CLIENT {self.client_id}_ERROR] Não é possível solicitar acesso, nenhuma sessão ativa.")
            return {"status": "error", "message": "Nenhuma sessão ativa."}

        request_payload = {
            "action": "request_access",
            "filename": filename,
            "access_type": access_type,
            "client_id": self.client_id,
            "session_id": self.session_id
        }
        print(f"[CLIENT {self.client_id}] Solicitando acesso de {access_type} para {filename}.")
        return self.send_request(request_payload)

    def release_access(self, filename, access_type):
        """
        Libera o acesso a um arquivo específico, informando ao servidor.

        Requer uma sessão ativa (ou seja, o cliente deve estar logado).

        Args:
            filename (str): O nome do arquivo do qual liberar o acesso.
            access_type (str): O tipo de acesso que está sendo liberado ('read' ou 'write').

        Returns:
            dict: A resposta do servidor para a requisição de liberação.
        """
        if not self.session_id:
            print(f"[CLIENT {self.client_id}_ERROR] Não é possível liberar acesso, nenhuma sessão ativa.")
            return {"status": "error", "message": "Nenhuma sessão ativa."}

        request_payload = {
            "action": "release_access",
            "filename": filename,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "access_type": access_type
        }
        print(f"[CLIENT {self.client_id}] Liberando acesso de {access_type} para {filename}.")
        return self.send_request(request_payload)

    def request_logout(self):
        """
        Envia uma requisição de logout ao servidor para encerrar a sessão atual do cliente.

        Se o logout for bem-sucedido, redefine o ID da sessão.

        Returns:
            dict: A resposta do servidor para a requisição de logout.
        """
        if not self.username or not self.session_id:
            print(f"[CLIENT {self.client_id}] Não logado ou sem sessão para fazer logout.")
            return {"status": "error", "message": "Não logado."}

        request_payload = {
            "action": "logout",
            "username": self.username,
            "session_id": self.session_id
        }
        print(f"[CLIENT {self.client_id}] Solicitando logout para o usuário: {self.username}")
        response = self.send_request(request_payload)
        if response.get("status") == "success":
            self.session_id = None
            print(f"[CLIENT {self.client_id}] Logout bem-sucedido.")
        else:
            print(f"[CLIENT {self.client_id}_ERROR] Logout falhou: {response.get('message')}")
        return response

    def simulate_work(self, max_operations=5):
        """
        Simula o fluxo de trabalho de um cliente, incluindo conexão, login,
        solicitação e liberação de acesso a arquivos e logout.

        Args:
            max_operations (int, opcional): O número máximo de operações de arquivo (leitura/escrita)
                                             a serem simuladas. Padrão para 5.
        """
        print(f"[CLIENT {self.client_id}] Iniciando simulação com {max_operations} operações.")

        try:
            self.connect()

            login_resp = self.request_login()
            if login_resp.get("status") != "success":
                print(f"[CLIENT {self.client_id}_ERROR] Falha ao fazer login. Abortando simulação. Resposta: {login_resp}")
                return

            for i in range(max_operations):
                action = random.choice(["read", "write"])
                file_name = random.choice(self.file_list)

                print(f"[CLIENT {self.client_id}] Operação {i+1}/{max_operations}: Solicitando acesso de {action} a {file_name}.")
                response = self.request_access(file_name, action)
                print(f"[CLIENT {self.client_id}] Resposta de acesso recebida para {file_name} ({action}): {response}")

                if response and response.get('status') == 'granted':
                    print(f"[CLIENT {self.client_id}] Trabalhando em {file_name} ({action}) por alguns segundos...")
                    work_time = random.randint(1, 5)
                    time.sleep(work_time)

                    release_resp = self.release_access(file_name, action)
                    print(f"[CLIENT {self.client_id}] Liberado {file_name} ({action}). Resposta: {release_resp}")
                else:
                    print(f"[CLIENT {self.client_id}] Acesso {action} a {file_name} foi {response.get('status')}. Mensagem: {response.get('message')}")

                time.sleep(random.uniform(0.5, 2.0))

            logout_resp = self.request_logout()
            print(f"[CLIENT {self.client_id}] Tentativa de logout resposta: {logout_resp}")

        except ConnectionRefusedError:
            print(f"[CLIENT {self.client_id}_FATAL] Conexão recusada. O servidor está rodando?")
        except Exception as e:
            print(f"[CLIENT {self.client_id}_FATAL] Encontrou um erro durante a simulação: {e}")
        finally:
            self.disconnect()

    def disconnect(self):
        """
        Fecha a conexão de socket com o servidor, se estiver ativa.
        """
        if self.socket:
            print(f"[CLIENT {self.client_id}] Desconectando socket.")
            self.socket.close()
            self.socket = None
        print(f"[CLIENT {self.client_id}] Conexão fechada.")


if __name__ == "__main__":
    print("[MAIN] Script do cliente iniciado.")
    FILES = ["fileA", "fileB", "fileC"]

    # Obtém o ID do cliente do nome do host do contêiner, se disponível
    container_client_id = os.getenv('HOSTNAME', 'default_client')

    # Mapeamentos de nome de usuário e senha baseados no ID do cliente
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

    print(f"[MAIN] Iniciando cliente {container_client_id} com usuário {client_user}")

    client = FileClient(
        client_id=container_client_id,
        file_list=FILES,
        username=client_user,
        password=client_pass,
        server_host='file-server' # Assume que o serviço do servidor está acessível via 'file-server' em um ambiente de contêiner.
    )

    client.simulate_work(max_operations=5)
    print(f"[MAIN] Simulação do cliente {container_client_id} finalizada.")
