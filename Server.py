import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import tkinter as tk
from tkinter import scrolledtext
import datetime

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

host = socket.gethostname()
port = 1001

# Create socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((host, port))
server_socket.listen(5)

print(f"Server listening on {host}:{port}")

clients = []

# Encryption and decryption functions
def encrypt(string, cipher):
    encryptor = cipher.encryptor()
    data = bytes(string, 'utf-8')
    data = append_hash(data)
    return encryptor.update(data) + encryptor.finalize()

def decrypt(data, cipher):
    decryptor = cipher.decryptor()
    byte_slice = decryptor.update(data) + decryptor.finalize()
    if not verify_hash(byte_slice):
        print("Invalid hash")
        exit(1)
    return str(byte_slice[:-32], 'utf-8')

def append_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()
    return data + hash_value

def verify_hash(data):
    message = data[:-32]
    append_hash = data[-32:]
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash = digest.finalize()
    return append_hash == hash

# Create the server chat window
server_chat_window = tk.Tk()
server_chat_window.geometry("400x400")
server_chat_window.title("Server Chat Page")
server_chat_text = scrolledtext.ScrolledText(server_chat_window, width=35, height=15)
server_chat_text.pack()
server_chat_window.withdraw()


def handle_client(connection, addr):
    global cipher
    print(f"Client connected: {addr}")

    # Key exchange
    connection.sendall(pem)

    try:
        aes_key = connection.recv(32)
        nonce = connection.recv(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))

        while True:
            cipher_data = connection.recv(1024)
            if not cipher_data:
                break
            decrypted_message = decrypt(cipher_data, cipher)
            if decrypted_message == "LOGIN_SUCCESS":
                server_chat_window.deiconify()
            server_chat_text.insert(tk.END, f'Client: {decrypted_message}\n')
            server_chat_text.yview(tk.END)
    except ConnectionResetError:
        print(f"Client connection reset: {addr}")

    connection.close()
    print(f"Client disconnected: {addr}")

def accept_connections():
    while True:
        connection, client_address = server_socket.accept()
        clients.append(connection)
        client_thread = threading.Thread(target=handle_client, args=(connection, client_address))
        client_thread.start()

accept_thread = threading.Thread(target=accept_connections)
accept_thread.start()

def send_message():
    plain_message = send_message_entry.get()
    for client in clients:
        client.sendall(encrypt(plain_message, cipher))
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    server_chat_text.insert(tk.END, f'You: {plain_message}  [{current_time}]\n')
    send_message_entry.delete(0, tk.END)
    server_chat_text.yview(tk.END)

send_message_entry = tk.Entry(server_chat_window, width=40)
send_message_entry.pack()
send_button = tk.Button(server_chat_window, text="Send", command=send_message)
send_button.pack()

server_chat_window.mainloop()

def handle_client(connection, addr):
    global cipher
    print(f"Client connected: {addr}")

    # Key exchange
    connection.sendall(pem)

    try:
        aes_key = connection.recv(32)
        nonce = connection.recv(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))

        while True:
            cipher_data = connection.recv(1024)
            if not cipher_data:
                break
            decrypted_message = decrypt(cipher_data, cipher)
            if decrypted_message == "LOGIN_SUCCESS":
                server_chat_window.deiconify()
            server_chat_text.insert(tk.END, f'Client: {decrypted_message}\n')
            server_chat_text.yview(tk.END)
    except ConnectionAbortedError:
        print(f"Client connection aborted: {addr}")

    connection.close()
    print(f"Client disconnected: {addr}")
