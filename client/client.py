import socket
import threading
import sys
from diffie_hellman import *

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


def start_client():
    # Conecta ao servidor
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, 8888))
    print("Connected to server.")

    # Envia o nome do cliente e o destinatário
    client_socket.send(operation.encode() + b" " + name.encode() + b" " + dest.encode())
    if operation == "login":
        with open(name + ".pem", "r") as f:
            lines = f.readlines()
            key = " ".join(lines)
            # Por algum motivo só envia correto se eu printar a chave
            print("Sending key: ", key)
            client_socket.send(key.encode())
            data = client_socket.recv(1024).decode()
            # Verifica se a autenticação foi bem sucedida
            if data == "Failed to authenticate":
                print(data)
                # Encerra a conexão caso a autenticação falhe
                client_socket.close()
                return
            elif data == "Authentication successful":
                print(data + ". You can now send messages." + "\n")
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
                print(data)
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
                # Salva a chave compartilhada no arquivo do cliente
                with open(name + "_shared_key.txt", "w") as f_shared_key:
                    f_shared_key.write(str(shared_key))
                
                # Recebe a chave pública RSA do servidor e salva no arquivo do cliente
                key = client_socket.recv(20000).decode()
                f.write(key)
                print("Key saved.")
            print("Client registered successfully. You can now send messages." + "\n")

    # Inicia a thread para receber mensagens
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    # Envia mensagens para o servidor
    while True:
        message = input("Enter message to send: ")
        if message == "exit":
            break
        client_socket.send(message.encode())

    client_socket.close()


if __name__ == "__main__":
    start_client()
