from Crypto.Random import get_random_bytes

if __name__ == "__main__":
    # Gerando a chave secreta para o arquivo de chaves
    secret_client_keys = get_random_bytes(16)
    with open("secret_client_keys.txt", "wb") as file:
        file.write(secret_client_keys.hex().encode())
    print("Secret key generated and saved to secret_client_keys.txt.")
