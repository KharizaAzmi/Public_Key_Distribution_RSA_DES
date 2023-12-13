import socket
import pickle
import random
from DES import des
from Counter import counter
import RSA

def generate_nonce():
    return random.randint(1000, 9999)

def receive_rsa_key(client_socket):
    data = client_socket.recv(4096)
    received_key_tuple = pickle.loads(data)
    return received_key_tuple

def generate_random_session_key(public_key):
    session_key = random.randint(1, public_key[1] - 1)
    return session_key

def handle_client(client_socket, session_key):
    while True:
        encrypted_message = client_socket.recv(4096)
        if not encrypted_message:
            break

        encrypted_message_str = encrypted_message.decode()

        print("------- Menerima pesan dari Alice (Client) -------")
        print(f"Pesan dari client: {encrypted_message_str}")
     
        decrypted_message = decrypt_message(session_key, encrypted_message_str)

        print(f"Pesan dari client yang sudah di decrypt: {decrypted_message}")

# Function to decrypt a message using DES
def decrypt_message(session_key, encrypted_message):
    counter_mode = counter()
    decrypted_message = counter_mode.decrypt(session_key, encrypted_message)
    return decrypted_message

# Function to encrypt a message using DES
def encrypt_message(session_key, message):
    counter_mode = counter()
    encrypted_message = counter_mode.encrypt(session_key, message)
    return encrypted_message.encode()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 5000))
    server.listen(1)

    print("Server listening on port 5000...")

    client_socket, client_address = server.accept()
    print(f"Connection from {client_address}")

    # Generate RSA keypair for the server
    server_keypair = RSA.generate_rsa_keypair(bits=1024)
    server_public_key, server_private_key = server_keypair
    

    # Send the server's public key to the client
    print("--- Server (Bob) send public key to client (Alice) ---")
    client_socket.sendall(pickle.dumps(server_public_key))

    # Receive the client's public key and ID
    client_public_key = receive_rsa_key(client_socket)

     # STEP 1
    print("[[STEP 1: ID Client dan N1 (nonce client) didecrypt menggunakan private key server]]")
    client_id = client_socket.recv(1024)
    client_id_decode = pickle.loads(client_id)
    decrypted_client_id = RSA.decrypt(client_id_decode, server_private_key)
    print(f"Decrypted client ID: {decrypted_client_id}")

    # nonce1 = client_socket.recv(4096).decode()
    encrypted_nonce1_encoded = client_socket.recv(4096)
    nonce1_decode = pickle.loads(encrypted_nonce1_encoded)
    decrypted_nonce1 = RSA.decrypt(nonce1_decode, server_private_key)

    # print(f"Encrypted nonce client using server public key : {nonce1_decode}")
    print(f"Decrypted nonce client using server private key: {decrypted_nonce1}")
    print("--------------------------------------------------------------------------")

    if decrypted_client_id == 12345:
        # STEP 2
        print("[[STEP 2: N1 (nonce client) dan N2 (nonce server) diencrypt menggunakan public key client (Bob --> Alice)]]")
        nonce2 = generate_nonce()
        encrypted_nonce2 = RSA.encrypt(nonce2, client_public_key)
        client_socket.sendall(pickle.dumps(encrypted_nonce2))
        # client_socket.sendall(str(nonce2).encode())
        print(f"Encrypted nonce server (N2) using client public key: {encrypted_nonce2}")
        # print(f"Nonce server: {nonce2}")

        encrypted_nonce1_puA = RSA.encrypt(decrypted_nonce1, client_public_key)
        client_socket.sendall(pickle.dumps(encrypted_nonce1_puA))
        print(f"Encrypted nonce client (N1) using client public key: {encrypted_nonce1_puA}")
        print("--------------------------------------------------------------------------")

        # STEP 3
        print("[[STEP 3: N2 (nonce server) didecrypt menggunakan private key server]]")
        encrypted_nonce2_encoded = client_socket.recv(4096)
        nonce2_decode = pickle.loads(encrypted_nonce2_encoded)
        decrypted_nonce2 = RSA.decrypt(nonce2_decode, server_private_key)
        # print(f"Encrypted nonce server using server public key: {nonce2_decode}")
        print(f"Decrypted nonce server using server private key: {decrypted_nonce2}")
        print("--------------------------------------------------------------------------")

        # STEP 4
        print("[[STEP 4: N1 (nonce client) dan Session Key diencrypt menggunakan public key client (Bob --> Alice)]]")
        # Generate a session key for DES using client public key
        encrypted_nonce1_puA2 = RSA.encrypt(decrypted_nonce1, client_public_key)
        client_socket.sendall(pickle.dumps(encrypted_nonce1_puA2))
        print(f"Encrypted nonce client (N1) using client public key: {encrypted_nonce1_puA2}")
        print("Session key digenerate menggunakan client public key kemudian di encrypt untuk dikirimkan kepada client")
        session_key = generate_random_session_key(client_public_key)

        # print(f"Client Public Key: {client_public_key}")
        print(f"Session key: {session_key}")
        encrypted_session_key = RSA.encrypt(session_key, client_public_key)
        print(f"Encrypted Session Key: {encrypted_session_key}")
    
        # Send the encrypted session key to the client
        client_socket.sendall(pickle.dumps(encrypted_session_key))

        # Continue the communication 
        handle_client(client_socket, session_key)

    client_socket.close()
    server.close()

if __name__ == "__main__":
    main()