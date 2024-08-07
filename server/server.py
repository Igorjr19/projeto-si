import socket
import threading
from Crypto.PublicKey import RSA
from diffie_hellman import *
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time

server_host = "localhost"
secret_client_keys_file = "./secret_client_keys.txt"
client_keys_file = "./client_keys.txt"
dh_constants_file = "./dh_constants.txt"
dh_keys_file = "./dh_keys.txt"

connected_clients = []
known_clients = []


def load_keys(rsa_keys_file, dh_keys_file):
    dh_keys = {}
    try :
        with open(dh_keys_file, "r") as file:
            while True:
                name = file.readline().strip()
                if not name:
                    break
                shared_key = file.readline().strip()

                dh_keys[name] = shared_key
    except:
        pass
    rsa_keys = []
    try :
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
    except:
        pass
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


def send_message(message, dest, clients, known_clients):
    # Criptografando e enviando a mensagem para o destinatário
    client_socket = None
    rsa_key = None
    for client in clients:
        if client["name"] == dest:
            client_socket = client["socket"]
            break
    for known_client in known_clients:
        if known_client["name"] == dest:
            rsa_key = known_client["public_key"]
            break
    if not rsa_key or not client_socket:
        return
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(rsa_key.public_key())
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    message = message.encode()
    cipher_text = cipher_aes.encrypt(message)
    
    nonce = cipher_aes.nonce
    client_socket.send(enc_session_key)
    time.sleep(0.01)
    client_socket.send(cipher_text)
    time.sleep(0.01)
    client_socket.send(nonce)


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

def recieve_message(client_socket, current_client):
    enc_session_key = client_socket.recv(1024)
    if not enc_session_key:
        return None
    cipher_text = client_socket.recv(1024)
    nonce = client_socket.recv(1024)
    
    rsa_key = current_client["private_key"]
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    message = cipher_aes.decrypt(cipher_text)
    plaintext = message.decode()
    return plaintext

def handle_client(client_socket, rsa_keys, dh_keys):
    # Separando o nome e o destinatário
    args = client_socket.recv(1024).decode().split()

    operation = args[0]

    # Adicionando o cliente à lista de clientes
    operation = args[0]
    if operation == "login":
        client = {
            "socket": client_socket,
            "name": args[1],
            "dest": args[2],
        }
    else:
        client = {
            "socket": client_socket,
            "name": args[1],
            "dest": "",
        }
    connected_clients.append(client)

    # Verificando se o cliente é conhecido
    known = False
    current_client = None
    for known_client in known_clients:
        if known_client["name"] == client["name"]:
            known = True
            current_client = known_client
            break

    if operation == "login" and known:
        plaintext = recieve_message(client_socket, current_client)
        if plaintext == "auth":
            print("Client", client["name"], "authenticated.")
            client_socket.send("Client authenticated".encode())
        else:
            print("Client", client["name"], "failed to authenticate.")
            client_socket.send("Client failed to authenticate".encode())
            client_socket.close()
            return
    elif operation == "register":
        # Caso o cliente não seja conhecido
        if not known:
            client_socket.send("Client registered successfully".encode())
            # Gerando as chaves de Diffie-Hellman
            dh_key = generate_dh_keys(client_socket, client["name"])
            # Gerando as chaves RSA
            rsa_key = RSA.generate(1024)
            # Enviando a chave RSA criptografada a partir de sua chave compartilhada (Diffie-Hellman) para o cliente
            print("Sending RSA key to client", client["name"])
            print("RSA key:", rsa_key.export_key().decode())
            client_socket.send(rsa_key.export_key().decode().encode())
            # Encriptando e salvando as chaves
            encrypt_and_save_keys(client["name"], rsa_key, client_keys_file, dh_key)
            # Adicionando o cliente à lista de clientes conhecidos
            new_client = {
                "name": client["name"],
                "private_key": rsa_key,
                "public_key": rsa_key.publickey(),
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
        # Decriptando a mensagem
        message = recieve_message(client_socket, current_client)
        if not message:
            break
        response = client["name"] + ": " + message
        # Enviando a mensagem para o destinatário
        send_message(response, client["dest"], connected_clients, known_clients)
    try :
        known_clients.remove(current_client)
    except:
        pass
    client_socket.close()


def start_server():
    # Inicializando o servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_host, 8888))
    server_socket.listen(5)
    print("Server started. Listening on port 8888...")

    # Carregando as chaves dos clientes do arquivo criptografado
    rsa_keys, dh_keys = load_keys(client_keys_file, dh_keys_file)
    if rsa_keys is not None:
        for key in rsa_keys:
            known_clients.append(key)
    # Aceitando conexões de clientes
    while True:
        client_socket, client_address = server_socket.accept()
        print("Accepted connection from:", client_address)
        client_thread = threading.Thread(
            target=handle_client,
            args=(
                client_socket,
                rsa_keys,
                dh_keys,
            ),
        )
        client_thread.start()


if __name__ == "__main__":
    start_server()
