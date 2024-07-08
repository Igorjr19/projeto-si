import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

server_host = "localhost"
secret_client_keys_file = "secret_client_keys.txt"
client_keys_file = "client_keys.bin"


def load_keys(filename, secret_key):
    # Carregando as chaves do arquivo
    with open(filename, "r") as file:
        file_len = len(file.readlines())
        file.seek(0)
        keys = []
        i = 0
        while True:
            if i >= file_len:
                break
            i += 1
            name = file.readline().strip()
            if not name:
                continue
            private_key_lines = []
            public_key_lines = []
            while True:
                i += 1
                line = file.readline().strip()
                private_key_lines.append(line)
                if line == "-----END ENCRYPTED PRIVATE KEY-----":
                    break
            while True:
                i += 1
                line = file.readline().strip()
                public_key_lines.append(line)
                if line == "-----END PUBLIC KEY-----":
                    break
            public_key_lines = "\n".join(public_key_lines) + "\n"
            private_key_lines = "\n".join(private_key_lines) + "\n"
            key = {
                "name": name,
                "private_key": RSA.import_key(private_key_lines, passphrase=secret_key),
                "public_key": RSA.import_key(public_key_lines, passphrase=secret_key),
            }
            keys.append(key)
        return keys


def encrypt_and_save_keys(client_name, key, filename, secret_key):

    # Separando a chave privada e pública e as criptografando
    private_key = key.export_key(
        passphrase=secret_key, pkcs=8, protection="scryptAndAES128-CBC"
    )
    public_key = key.publickey().export_key(
        passphrase=secret_key, pkcs=8, protection="scryptAndAES128-CBC"
    )
    private_key = private_key.decode()
    public_key = public_key.decode()

    # Salvando as chaves criptografadas
    save_keys(client_name, private_key, public_key, filename)


def save_keys(client_name, private_key, public_key, filename):
    # Salvando a chave privada e pública do cliente
    with open(filename, "a") as file:
        file.write(client_name + "\n")
        file.write(private_key + "\n")
        file.write(public_key + "\n\n")


def send_message(message, dest, clients):
    for client in clients:
        if client["name"] == dest:
            client["socket"].send(message.encode())
            break


def handle_client(client_socket, connected_clients, know_clients, secret_client_keys):
    # Separando o nome e o destinatário
    args = client_socket.recv(1024).decode().split()

    operation = args[0]
    
    # Adicionando o cliente à lista de clientes
    client = {
        "socket": client_socket,
        "name": args[1],
        "dest": args[2],
    }
    connected_clients.append(client)
    
    # Verificando se o cliente é conhecido
    known = False
    for known_client in know_clients:
        if known_client["name"] == client["name"]:
            known = True
            break
    
    if operation == "login" and known:
        data = client_socket.recv(20000)
        client_key = RSA.import_key(data.decode(), passphrase=secret_client_keys)
        # Verificando se a chave do cliente é a mesma que a chave conhecida
        if client_key.publickey().export_key() == known_client["public_key"].export_key():
            # Enviando a confirmação de autenticação
            print("Client", client["name"], "logged in.")
            client_socket.send("Authentication successful".encode())
        else:
            # Enviando a falha de autenticação e encerrando a conexão
            print("Client", client["name"], "failed to log in.")
            client_socket.send("Failed to authenticate".encode())
            client_socket.close()
                
    elif operation == "register":
        # Caso o cliente não seja conhecido
        if not known:
            # Gerando as chaves RSA
            key = RSA.generate(1024)
            # Encriptando e salvando as chaves
            encrypt_and_save_keys(client["name"], key, client_keys_file, secret_client_keys)
            # Adicionando o cliente à lista de clientes conhecidos
            new_client = {
                "name": client["name"],
                "private_key": key,
                "public_key": key.publickey(),
            }
            know_clients.append(new_client)
        
    # Recebendo mensagens do cliente
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        response = client["dest"] + ": " + data.decode()
        # Enviando a mensagem para o destinatário
        send_message(response, client["dest"], connected_clients)
    connected_clients.remove(client_socket)
    client_socket.close()


def start_server():
    # Inicializando o servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_host, 8888))
    server_socket.listen(5)
    print("Server started. Listening on port 8888...")

    connected_clients = []
    known_clients = []

    # Lendo a chave secreta do arquivo
    secret_client_keys = open(secret_client_keys_file, "rb").read().decode()
    secret_client_keys = bytes.fromhex(secret_client_keys)
    
    # Carregando as chaves dos clientes do arquivo criptografado
    keys = load_keys(client_keys_file, secret_client_keys)
    if keys is not None:
        for key in keys:
            known_clients.append(key)      

    # Aceitando conexões de clientes
    while True:
        client_socket, client_address = server_socket.accept()
        print("Accepted connection from:", client_address)
        client_thread = threading.Thread(
            target=handle_client, args=(client_socket, connected_clients, known_clients, secret_client_keys)
        )
        client_thread.start()


if __name__ == "__main__":
    start_server()
