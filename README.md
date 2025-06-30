# Sistema de Controle de Acesso a Arquivos

Este projeto implementa um sistema simplificado de controle de acesso a arquivos usando uma arquitetura cliente-servidor. O servidor gerencia recursos de arquivo, autenticação de usuários e permissões de acesso, incluindo bloqueios de leitura/escrita com um mecanismo de fila. Vários clientes podem se conectar ao servidor, autenticar e solicitar acesso a arquivos.

-----

## Funcionalidades

  * **Arquitetura Cliente-Servidor:** Componentes separados para servidor e clientes.
  * **Autenticação de Usuário:** Usuários fazem login com nome de usuário e senha.
  * **Controle de Acesso Baseado em Função (RBAC):** Os arquivos possuem permissões de leitura e escrita definidas com base nas funções do usuário.
  * **Gerenciamento de Sessão:** Cada login bem-sucedido gera um ID de sessão para solicitações subsequentes. As sessões são validadas e podem ser invalidadas (por exemplo, ao fazer logout ou login concorrente).
  * **Bloqueio de Arquivos:**
      * Vários leitores são permitidos simultaneamente.
      * Apenas um escritor é permitido por vez.
      * Nenhum leitor é permitido quando um escritor está ativo.
  * **Enfileiramento de Solicitações (FIFO):** Se um arquivo estiver bloqueado, novas solicitações são adicionadas a uma fila FIFO, e os clientes esperam sua vez.
  * **Registro (Logging):** Eventos do servidor, incluindo conexões, solicitações, concessões/negações de acesso e desconexões, são registrados em um arquivo.
  * **Implantação Dockerizada:** Todo o sistema pode ser facilmente implantado usando Docker Compose.

-----

## Estrutura do Projeto

```
.
├── docker-compose.yml
├── server.py
├── client.py
├── .gitignore
└── README.md
```

  * `docker-compose.yml`: Define os serviços Docker para o servidor e vários clientes.
  * `server.py`: Contém as classes `FileServer` e `FileResource`, implementando a lógica central para controle de acesso a arquivos, autenticação e *threading*.
  * `client.py`: Contém a classe `FileClient`, que simula o comportamento do usuário (login, solicitação de acesso, liberação de acesso, logout).

-----

## Primeiros Passos

### Pré-requisitos

  * Docker Desktop (ou Docker Engine e Docker Compose) instalado em seu sistema.

### Executando a Aplicação

1.  **Clone o Repositório (se ainda não o fez):**

    ```bash
    git clone git@github.com:AlexiaCordeiro/controle_acesso.git
    cd <diretorio-do-seu-repositorio>
    ```

2.  **Construa e Execute com Docker Compose:**
    Navegue até o diretório raiz do projeto (onde está localizado `docker-compose.yml`) e execute:

    ```bash
    docker-compose up --build
    ```

    Este comando irá:

      * Construir as imagens Docker `file-server` e `file-client`.
      * Iniciar o contêiner `file-server`.
      * Iniciar três contêineres `file-client` (`file-client-1`, `file-client-2`, `file-client-3`), cada um simulando a atividade do usuário.

3.  **Observe os Logs:**
    Os logs de todos os serviços (servidor e clientes) serão exibidos no seu terminal. Você verá:

      * Clientes conectando e fazendo login.
      * Clientes solicitando e liberando acesso a arquivos.
      * Servidor concedendo ou negando acesso com base em permissões e bloqueios.
      * Solicitações sendo enfileiradas.

    Para visualizar os logs em um terminal separado após iniciar:

    ```bash
    docker-compose logs -f
    ```

    Para visualizar os logs de um serviço específico (por exemplo, `file-server`):

    ```bash
    docker-compose logs -f file-server
    ```

4.  **Pare a Aplicação:**
    Para parar e remover os contêineres, redes e imagens criados por `docker-compose up`, pressione `Ctrl+C` no terminal onde `docker-compose up` está sendo executado e, em seguida, execute:

    ```bash
    docker-compose down
    ```

-----

## Configuração

### Servidor (`server.py`)

  * **Usuários e Senhas:**
    O dicionário `self.users` em `FileServer.__init__` define os nomes de usuário válidos, senhas e suas funções.
    ```python
    self.users = {
        "user1": {"password": "password1", "roles": ["admin"]},
        "user2": {"password": "password2", "roles": ["user"]},
        "user3": {"password": "password3", "roles": ["guest"]}
    }
    ```
  * **Arquivos e Permissões:**
    O dicionário `self.files` define os arquivos disponíveis, seus proprietários e as permissões de leitura/escrita para cada função.
    ```python
    self.files = {
        "fileA": {"owner": "user1", "permissions": {"read": ["admin", "user", "guest"], "write": ["admin", "user"]}},
        "fileB": {"owner": "user2", "permissions": {"read": ["admin", "user"], "write": ["admin"]}},
        "fileC": {"owner": "user1", "permissions": {"read": ["admin"], "write": ["admin"]}}
    }
    ```

### Cliente (`client.py`)

  * **Operações Simuladas:**
    `client.simulate_work(max_operations=5)` no bloco `if __name__ == "__main__":` controla quantas operações de arquivo cada cliente executa.
  * **Lista de Arquivos:**
    A lista `FILES` determina quais arquivos os clientes solicitarão acesso aleatoriamente. Isso deve corresponder aos arquivos definidos no servidor.
    ```python
    FILES = ["fileA", "fileB", "fileC"]
    ```
  * **Atribuição de Usuário (Docker):**
    Os clientes são atribuídos a usuários com base no nome do serviço Docker (hostname). Esse mapeamento está no bloco `if __name__ == "__main__":` do `client.py`:
    ```python
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
    ```

-----

## Como Funciona (Detalhes Técnicos)

### Servidor (`server.py`)

  * **Classe `FileResource`:**

      * Cada arquivo no servidor tem um objeto `FileResource` associado.
      * Ele usa um objeto `threading.Condition` para gerenciar o acesso concorrente.
      * `readers`: Conta os leitores ativos (vários podem manter um bloqueio de leitura).
      * `writer_active`: Sinalizador booleano para um escritor ativo (bloqueio exclusivo).
      * `pending_requests`: Uma `deque` (fila de duas extremidades) para manter uma ordem FIFO para as solicitações recebidas.
      * `acquire_read`/`acquire_write`: Métodos que bloqueiam (usando `condition.wait()`) se o acesso solicitado não puder ser concedido imediatamente, com base nas regras de leitura/escrita e na ordem da fila.
      * `release_read`/`release_write`: Métodos para liberar bloqueios e notificar *threads* em espera (`condition.notify_all()`).

  * **Classe `FileServer`:**

      * Inicializa o *socket* do servidor, dados do usuário, permissões de arquivo e instâncias `FileResource` para cada arquivo.
      * `logged_in_users`: Armazena sessões de usuário ativas (`username: {session_id, role, addr}`).
      * `authenticate_user`: Lida com o login do usuário, gera IDs de sessão e gerencia logins concorrentes para o mesmo usuário.
      * `check_file_access_permissions`: Verifica se a função de um usuário tem a permissão estática para um determinado arquivo e tipo de acesso. Esta é a primeira camada de permissão.
      * `request_file_access`:
        1.  Primeiro, chama `check_file_access_permissions` para garantir que o usuário tenha a permissão básica baseada em função.
        2.  Se as permissões forem concedidas, a solicitação é adicionada à fila `FileResource.pending_requests`.
        3.  Em seguida, tenta adquirir o bloqueio de leitura/escrita usando `FileResource.acquire_read`/`acquire_write`. Esta chamada será bloqueada até que a solicitação esteja no início da fila e o bloqueio possa ser adquirido.
      * `release_file_access`: Libera o bloqueio correspondente no `FileResource`.
      * `handle_client`: Uma função *threaded* para cada conexão de cliente. Ela gerencia:
          * Recebimento e análise de solicitações de clientes.
          * **Autenticação Multi-camadas:**
            1.  Verifica se a própria *thread* `handle_client` possui um `current_user` e `session_id` estabelecidos (a partir de um login bem-sucedido anterior).
            2.  Compara o `session_id` enviado na *carga útil da solicitação atual* com o `session_id` armazenado *localmente na *thread**.
            3.  Verifica se o `session_id` na *thread* local ainda corresponde ao que está no dicionário global `self.logged_in_users` (para detectar logins concorrentes invalidando uma sessão antiga).
          * Chamando os métodos apropriados (`request_file_access`, `release_file_access`, `logout_user`).
          * Enviando respostas de volta ao cliente.
          * Lida com desconexões de clientes e limpa os dados da sessão.

### Cliente (`client.py`)

  * **Classe `FileClient`:**
      * Conecta-se ao servidor.
      * `request_login`, `request_access`, `release_access`, `request_logout`: Métodos para enviar solicitações específicas formatadas em JSON para o servidor. Cada solicitação (exceto login) inclui o `session_id`.
      * `simulate_work`: Um *loop* que escolhe aleatoriamente arquivos e tipos de acesso (`read`/`write`), solicita acesso, simula trabalho (dorme) e, em seguida, libera o acesso. Ele lida com login/logout antes/depois das operações.
      * Usa variáveis de ambiente (`SERVER_HOST`, `HOSTNAME`) para integração com Docker, permitindo que os clientes encontrem o servidor pelo nome do seu serviço.


