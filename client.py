import socket
import threading
import sys

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
    if (operation == "login"):
        with open(name + ".pem", "r") as f:
            lines = f.readlines()
            key = " ".join(lines)
            # Por algum motivo só envia correto se eu printar a chave
            print("Sending key: ", key)
            client_socket.send(key.encode())
            data = client_socket.recv(1024).decode()
            if data == "Failed to authenticate":
                print(data)
                client_socket.close()
                return
            elif data == "Authentication successful":
                print(data + ". You can now send messages." + "\n")
    elif (operation == "register"):
        pass
    
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
