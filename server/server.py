import socket
import threading
from Crypto.PublicKey import RSA
from diffie_hellman import *
from Crypto.Hash import SHA256

server_host = "localhost"
secret_client_keys_file = "./secret_client_keys.txt"
client_keys_file = "./client_keys.txt"
dh_constants_file = "./dh_constants.txt"
dh_keys_file = "./dh_keys.txt"

connected_clients = []
known_clients = []


def load_keys(rsa_keys_file, dh_keys_file):
    dh_keys = {}
    with open(dh_keys_file, "r") as file:
        while True:
            name = file.readline().strip()
            if not name:
                break
            shared_key = file.readline().strip()
            
            dh_keys[name] = shared_key
    rsa_keys = []
    with open(rsa_keys_file, "r") as file:
        file_len = len(file.readlines())
        file.seek(0)
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
            secret_key = dh_keys[name]
            key = {
                "name": name,
                "private_key": RSA.import_key(private_key_lines, passphrase=secret_key),
                "public_key": RSA.import_key(public_key_lines, passphrase=secret_key),
            }
            rsa_keys.append(key)
        return rsa_keys, dh_keys


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


def generate_dh_keys(client_socket, client_name):
    # Gerando os valores de p e g para Diffie-Hellman
    p, g = generate_base_and_modulus_dh()
    p = int(p)
    g = int(g)
    # Gerando as chaves de Diffie-Hellman para o servidor
    private_key_dh = generate_private_key_dh(p)
    public_key_dh = generate_public_key_dh(g, private_key_dh, p)
    # Enviando a chave pública para o cliente
    client_socket.send(f"{str(p)} {str(g)} {str(public_key_dh)}".encode())
    # Recebendo a chave pública do cliente
    other_public_key_dh = client_socket.recv(1024).decode()
    other_public_key_dh = int(other_public_key_dh)
    # Calculando a chave compartilhada
    shared_key = compute_shared_secret_dh(other_public_key_dh, private_key_dh, p)
    # Utilizando SHA-256 para gerar a chave simétrica
    shared_key = SHA256.new(str(shared_key).encode()).hexdigest()

    # Salvando as chaves de Diffie-Hellman no arquivo
    with open(dh_keys_file, "a") as file:
        file.write(client_name + "\n")
        file.write(str(shared_key) + "\n")
    return shared_key


def handle_client(client_socket, rsa_keys, dh_keys):
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
    for known_client in known_clients:
        if known_client["name"] == client["name"]:
            known = True
            break

    if operation == "login" and known:
        data = client_socket.recv(20000)
        for known_client in known_clients:
            if known_client["name"] == client["name"]:
                break
        dh_key = dh_keys[client["name"]]
        client_key = RSA.import_key(data.decode(), passphrase=dh_key)
        # Verificando se a chave do cliente é a mesma que a chave conhecida
        if (
            client_key.publickey().export_key()
            == known_client["public_key"].export_key()
        ):
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
            client_socket.send("Client registered successfully".encode())
            # Gerando as chaves de Diffie-Hellman
            dh_key = generate_dh_keys(client_socket, client["name"])
            # Gerando as chaves RSA
            key = RSA.generate(1024)
            # TODO - Fazer de forma segura
            # Enviando a chave RSA para o cliente
            client_socket.send(key.export_key().decode().encode())
            # Encriptando e salvando as chaves
            encrypt_and_save_keys(
                client["name"], key, client_keys_file, dh_key
            )
            # Adicionando o cliente à lista de clientes conhecidos
            new_client = {
                "name": client["name"],
                "private_key": key,
                "public_key": key.publickey(),
            }
            known_clients.append(new_client)
            print("Client", client["name"], "registered.")
        else:
            # Caso o cliente seja conhecido
            print("Client", client["name"], "already registered.")
            client_socket.send("Client already registered".encode())
            client_socket.close()
            return

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

    # Lendo a chave secreta do arquivo
    # secret_client_keys = open(secret_client_keys_file, "rb").read().decode()
    # secret_client_keys = bytes.fromhex(secret_client_keys)

    # Carregando as chaves dos clientes do arquivo criptografado
    rsa_keys, dh_keys = load_keys(client_keys_file, dh_keys_file)
    if rsa_keys is not None:
        for key in rsa_keys:
            known_clients.append(key["name"])

    # Aceitando conexões de clientes
    while True:
        client_socket, client_address = server_socket.accept()
        print("Accepted connection from:", client_address)
        client_thread = threading.Thread(
            target=handle_client, args=(client_socket, rsa_keys, dh_keys,)
        )
        client_thread.start()


if __name__ == "__main__":
    start_server()
