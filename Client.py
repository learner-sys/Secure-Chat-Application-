import os
import sqlite3
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
import hashlib
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from threading import Thread
import datetime

main_window = tk.Tk()
main_window.title("Sign In")
main_window.geometry("400x400")
main_signin_label = tk.Label(main_window, text="SIGN IN")
main_signin_label.pack()
main_username_label = tk.Label(main_window, text="Username:")
main_username_label.pack()
main_username_entry = tk.Entry(main_window)
main_username_entry.pack()
main_password_label = tk.Label(main_window, text="Password:")
main_password_label.pack()
main_password_entry = tk.Entry(main_window, show="*")
main_password_entry.pack()
host = socket.gethostname()

conn = sqlite3.connect('user_database.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, 1001))
server_public_key = load_pem_public_key(client_socket.recv(1024))
aes_key = os.urandom(32)
nonce = os.urandom(16)
client_socket.sendall(aes_key)
client_socket.sendall(nonce)
cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))

def encrypt(string):
    encryptor = cipher.encryptor()
    data = bytes(string, 'utf-8')
    data = append_hash(data)
    return encryptor.update(data) + encryptor.finalize()

def decrypt(data):
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

def login_user():
    username = main_username_entry.get()
    password = main_password_entry.get()
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    user = cursor.fetchone()
    if user is None:
        messagebox.showerror("Error", "Username does not exist. Please sign up first.")
        return
    stored_password = user[1]
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if hashed_password == stored_password:
        messagebox.showinfo("Success", "Welcome, {}! You have signed in successfully.".format(username))
        main_window.withdraw()
        client_socket.sendall(encrypt("LOGIN_SUCCESS"))
        chat_window.deiconify()
    else:
        messagebox.showerror("Error", "Incorrect password. Please try again.")

def sign_up_user():
    username =main_username_entry.get()
    password = main_password_entry.get()
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    user = cursor.fetchone()
    if user is not None:
        messagebox.showerror("Error", "Username already exists. Please choose another one.")
        return
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    messagebox.showinfo("Success", "User signed up successfully. You can now log in.")
    main_username_entry.delete(0, tk.END)
    main_password_entry.delete(0, tk.END)

sign_in_button = tk.Button(main_window, text="Sign In", command=login_user)
sign_in_button.pack()
sign_up_button = tk.Button(main_window, text="Sign Up", command=sign_up_user)
sign_up_button.pack()

chat_window = tk.Toplevel(main_window)
chat_window.geometry("400x400")
chat_window.title("Client Chat Page")
chat_text = ScrolledText(chat_window, width=50, height=20)
chat_text.pack()
chat_text.configure(state='disabled')
chat_window.withdraw()
send_message_entry = tk.Entry(chat_window, width=40)
send_message_entry.pack()
send_button = tk.Button(chat_window, text="Send", command=lambda: send_message(client_socket))
send_button.pack()

def receive_message():
    while True:
        try:
            cipher_data = client_socket.recv(1024)
            if not cipher_data:
                break
            decrypted_message = decrypt(cipher_data)
            chat_text.configure(state='normal')
            chat_text.insert(tk.END, f'Server: {decrypted_message}\n')
            chat_text.configure(state='disabled')
            chat_text.yview(tk.END)
        except Exception as e:
            print(f"Error: {e}")
            break

def send_message(client_socket):
    plain_message = send_message_entry.get()
    client_socket.sendall(encrypt(plain_message))
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    chat_text.configure(state='normal')
    chat_text.insert(tk.END, f'You: {plain_message}  [{current_time}]\n')
    send_message_entry.delete(0, tk.END)
    chat_text.configure(state='disabled')
    chat_text.yview(tk.END)

receive_thread = Thread(target=receive_message)
receive_thread.start()
main_window.mainloop()
conn.close()