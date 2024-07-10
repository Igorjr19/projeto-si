import socket
import threading
import sys
from diffie_hellman import *
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import time

operation = sys.argv[1]
name = sys.argv[2]
dest = sys.argv[3]
server_host = "localhost"


def receive_messages(client_socket):
    # Recebe mensagens do servidor
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        print("\nReceived message from", data.decode())
        print("Enter message to send: ", end="", flush=True)


def send_message():
    # TODO - Implementar a criptografia da mensagem
    # Envia mensagens para o servidor
    message = input("Enter message to send: ")
    return message


def start_client():
    # Conecta ao servidor
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, 8888))
    print("Connected to server.")

    rsa_key = ""
    dh_key = ""

    # Envia o nome do cliente e o destinatário
    client_socket.send(operation.encode() + b" " + name.encode() + b" " + dest.encode())
    if operation == "login":
        with open(name + ".pem", "r") as f:
            with open(name + "_shared_key.txt", "r") as f_shared_key:
                shared_key = f_shared_key.read()
                rsa_key = f.read()
                rsa_key = RSA.import_key(rsa_key, passphrase=shared_key)

                session_key = get_random_bytes(16)

                cipher_rsa = PKCS1_OAEP.new(rsa_key.public_key())
                enc_session_key = cipher_rsa.encrypt(session_key)

                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                auth_message = "auth".encode()
                cipher_text = cipher_aes.encrypt(auth_message)
                
                nonce = cipher_aes.nonce
                client_socket.send(enc_session_key)
                time.sleep(0.01)
                client_socket.send(cipher_text)
                time.sleep(0.01)
                client_socket.send(nonce)
                data = client_socket.recv(1024).decode()
                print(data)

    elif operation == "register":
        with open(name + ".pem", "w") as f:
            data = client_socket.recv(1024).decode()
            # Verifica se o cliente já está registrado
            if data == "Client already registered":
                print(data)
                # Encerra a conexão caso o cliente já esteja registrado
                client_socket.close()
                return
            elif data == "Client registered successfully":
                # Recebe as chaves de Diffie-Hellman do servidor
                data = client_socket.recv(1024).decode()
                p, g, server_public_key = data.split()
                # Gera as chaves de Diffie-Hellman
                private_key = generate_private_key_dh(int(p))
                public_key = generate_public_key_dh(int(g), private_key, int(p))
                # Envia a chave pública para o servidor
                client_socket.send(str(public_key).encode())
                # Calcula a chave compartilhadaS
                shared_key = compute_shared_secret_dh(
                    int(server_public_key), private_key, int(p)
                )
                # Utilizando SHA-256 para gerar a chave simétrica
                shared_key = SHA256.new(str(shared_key).encode()).hexdigest()
                # Salva a chave compartilhada no arquivo do cliente
                with open(name + "_shared_key.txt", "w") as f_shared_key:
                    f_shared_key.write(str(shared_key))
                # Recebe a chave pública RSA do servidor e salva no arquivo do cliente
                key = client_socket.recv(20000).decode()
                print("Received key: ", key)
                f.write(key)
                print("Key saved.")
                print("Client registered successfully.")
                print("Login to start sending messages.")
                # Encerra a conexão
                client_socket.close()
                return

    # Inicia a thread para receber mensagens
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    # Envia mensagens para o servidor
    while True:
        # TODO - Encriptar a mensagem
        message = send_message()
        if message == "exit":
            break
        client_socket.send(message.encode())

    client_socket.close()


if __name__ == "__main__":
    start_client()
