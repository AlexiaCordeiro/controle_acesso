🔧 Requisitos
Python 3.6+

Bibliotecas padrão (socket, threading, json, time, random, collections)

1. Iniciar o Servidor
  python server.py
O servidor escutará na porta 5000 do localhost por padrão. Os logs serão registrados em server_log.txt.

2. Iniciar os Clientes
   python client.py
Esse script simula múltiplos clientes acessando arquivos simultaneamente. Por padrão, 5 clientes são iniciados, cada um solicitando acesso de leitura ou escrita a arquivos fictícios (file1.txt, file2.txt, etc).

Pode-se alterar a lista de arquivos, ações e número de clientes diretamente no final do client.py:
  FILES = ["file1.txt", "file2.txt", "file3.txt"]
  ACTIONS = ["read", "write"]
  CLIENTS = 5

Testes e Comportamento Esperado
- Os clientes solicitam acesso aos arquivos.
- O servidor controla o acesso com base em locks e fila FIFO, garantindo exclusão mútua.
- Clientes aguardam quando o acesso está bloqueado.
- Após o uso, os arquivos são liberados e o próximo na fila é atendido.
- Toda atividade é logada no servidor.
