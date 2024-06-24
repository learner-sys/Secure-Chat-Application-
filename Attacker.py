import socket

def attack():
    attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 1001

    try:
        # Attempt to connect to the server
        attacker_socket.connect((host, port))
        print("Connected to server.")

        # Malicious key exchange to match protocol
        aes_key = attacker_socket.recv(32)
        nonce = attacker_socket.recv(16)

        # Send a malicious message to the server
        attacker_socket.sendall(b"ATTACK_MESSAGE")
        print("Attack message sent.")

    except ConnectionRefusedError as e:
        print(f"Connection failed: {e}")
    finally:
        attacker_socket.close()
        print("Connection closed.")


if __name__ == "__main__":
    attack()