import socket
import pickle
import random
from Counter import counter
from DES import des
import RSA


def generate_nonce():
    return random.randint(1000, 9999)

def receive_rsa_key(server_socket):
    data = server_socket.recv(4096)
    received_key_tuple = pickle.loads(data)
    received_public_key = received_key_tuple
    return received_public_key

def receive_session_key(client_socket, private_key):
    encrypted_session_key_encoded = client_socket.recv(4096)
   
    session_key_decode = pickle.loads(encrypted_session_key_encoded)

    print(f"Encrypted session key: {session_key_decode}")
    
    session_key = RSA.decrypt(session_key_decode, private_key)
    # Konversi kembali session key ke dalam bentuk string binary
    print(f"Decrypted session key: {session_key}")
    return session_key

# Continue the communication using the session key
def communicate_with_session_key(server, session_key, nonce):
    while True:
        # Get a message from the user or another source
        print("------ Ketik pesan untuk di kirim ke Bob (Server) -------")
        user_input = input("Enter a message (or 'q' to quit): ")
        if user_input.lower() == 'q':
            break

        # Encrypt the message using DES
        # print(f"Session Key: {session_key}")
        encrypted_message = encrypt_message(session_key, user_input)

        # Send the encrypted message to the server
        server.sendall(encrypted_message.encode())

        print(f"Pesan yang dikirimkan: {encrypted_message}")


# Function to decrypt a message using DES
def decrypt_message(session_key, encrypted_message):
    counter_mode = counter()
    print("Converted Key:", session_key)
    decrypted_message = counter_mode.decrypt(session_key, encrypted_message)
    return decrypted_message

# Function to encrypt a message using DES
def encrypt_message(session_key, message):
    counter_mode = counter()
    encrypted_message = counter_mode.encrypt(session_key, message)
    return encrypted_message

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 5000))

    # Receive the server's public key
    server_public_key = receive_rsa_key(client_socket)
    # print(f"Server public key: {server_public_key}")

    # Generate RSA keypair for the client
    client_keypair = RSA.generate_rsa_keypair(bits=1024)
    client_public_key, client_private_key = client_keypair

    # print(f"Client public key: {client_public_key}")
    # print(f"Client private key: {client_private_key}")

    # Send the client's public key to the server
    print("--- Client (Alice) send public key to Bob (Server) ---")
    client_socket.sendall(pickle.dumps(client_public_key))

    # STEP 1
    print("[[STEP 1: ID Client dan N1 (nonce client) diencrypt menggunakan public key server (Alice --> Bob)]]")
    # Send the client's ID to the server
    client_id = 12345  # Set the client ID
    encrypted_client_id = RSA.encrypt(client_id, server_public_key)
    client_socket.sendall(pickle.dumps(encrypted_client_id))
    print(f"Encrypted client ID: {client_id}")

    nonce1 = generate_nonce()
    encrypted_nonce1 = RSA.encrypt(nonce1, server_public_key)
    client_socket.sendall(pickle.dumps(encrypted_nonce1))
    print(f"Encrypted nonce client using server public key: {encrypted_nonce1}")
    # print(f"Nonce client: {nonce1}")
    print("--------------------------------------------------------------------------")

    # STEP 2
    print("[[STEP 2: N1 (nonce client) dan N2 (nonce server) didecrypt menggunakan private key client]]")
    encrypted_nonce1_encoded = client_socket.recv(4096)
    nonce1_decode = pickle.loads(encrypted_nonce1_encoded)
    decrypted_nonce1_puA = RSA.decrypt(nonce1_decode, client_private_key)

    # print(f"Encrypted nonce client using client public key: {nonce1_decode}")
    print(f"Decrypted nonce client using client private key: {decrypted_nonce1_puA}")

    # client_socket.sendall(str(nonce1).encode())
    encrypted_nonce2_encoded = client_socket.recv(4096)
    nonce2_decode = pickle.loads(encrypted_nonce2_encoded)
    decrypted_nonce2 = RSA.decrypt(nonce2_decode, client_private_key)

    # print(f"Encrypted nonce server using client public key: {nonce2_decode}")
    print(f"Decrypted nonce server using client private key: {decrypted_nonce2}")
    print("--------------------------------------------------------------------------")

    # STEP 3
    print("[[STEP 3: N2 (nonce server) diencrypt menggunakan public key server (Alice --> Bob)]]")
    encrypted_nonce2_puB = RSA.encrypt(decrypted_nonce2, server_public_key)
    client_socket.sendall(pickle.dumps(encrypted_nonce2_puB))
    print(f"Encrypted nonce server using server public key: {encrypted_nonce2_puB}")
    print("--------------------------------------------------------------------------")

    # STEP 4
    print("[[STEP 4: N1 (nonce client) dan Session Key didecrypt menggunakan private key client]]")
    print("Session key didecrypt kemudian digunakan untuk encrypt pesan menggunakan DES")
    # Continue with communication using the session key, ID, and nonce
    # Receive the session key from the server
    encrypted_nonce1_encoded2 = client_socket.recv(4096)
    nonce1_decode2 = pickle.loads(encrypted_nonce1_encoded2)
    decrypted_nonce1_puA2 = RSA.decrypt(nonce1_decode2, client_private_key)
    # print(f"Encrypted nonce client using client public key: {nonce1_decode}")
    print(f"Decrypted nonce client using client private key: {decrypted_nonce1_puA2}")
    session_key = receive_session_key(client_socket, client_private_key)

    # Continue the communication using the session key
    communicate_with_session_key(client_socket, session_key, nonce1)

    client_socket.close()

if __name__ == "__main__":
    main()