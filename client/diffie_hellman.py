import random
from Crypto.Util.number import getPrime

# Função para gerar a raiz primitiva de um número primo
def primitive_root(p):
    if p == 2:
        return 1
    p1 = 2
    p2 = (p-1) // p1

    while True:
        g = random.randint(2, p-1)
        if pow(g, (p-1)//p1, p) != 1 and pow(g, (p-1)//p2, p) != 1:
            return g

# Função para gerar um número primo e sua raiz primitiva
def generate_base_and_modulus_dh(length=1024):
    p = getPrime(length)
    g = primitive_root(p)
    return p, g

# Função para gerar a chave privada
def generate_private_key_dh(p):
    private_key = random.randint(2, p-2)
    return private_key

# Função para gerar a chave pública
def generate_public_key_dh(g, private_key, p):
    public_key = pow(g, private_key, p)
    return public_key

# Função para computar o segredo compartilhado
def compute_shared_secret_dh(other_public_key, private_key, p):
    shared_secret = pow(other_public_key, private_key, p)
    return shared_secret