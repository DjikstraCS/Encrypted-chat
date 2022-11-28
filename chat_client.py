#!/usr/bin/env python3
"""Script for encrypted Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, SealedBox


secretKey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE) # Generate secret key for symetric encrytion.
box = nacl.secret.SecretBox(secretKey) # Create safe, needed to encrypt and decrypt messages.


def receive():
    """Handles receiving of messages."""

    pubKeyServer = nacl.public.PublicKey(client_socket.recv(BUFSIZ)) # Recieve public key.
    sealed_box = SealedBox(pubKeyServer) # Create sealed box with server public key, needed to encrypt secret key.
    encrypted = sealed_box.encrypt(secretKey) # Encrypt secret key.
    client_socket.send(bytes(encrypted)) # Send encrypted secret key to server.
    
    while True:
        try:
            msg_decrypted = box.decrypt(client_socket.recv(BUFSIZ)) # Recieve and decrypt message.
            msg_list.insert(tkinter.END, msg_decrypted) # Insert message in the GUI message field.
        except OSError:
            break

def send(event=None):
    """Handles sending of messages."""
    
    msg = bytes(my_msg.get(), 'utf8') # Get message from GUI text field, it's a string so it needs utf-8 encoding.
    my_msg.set("")  # Clears GUI text field.
    client_socket.send(bytes(box.encrypt(msg))) # Encrypt and send message.
    
    if msg == "!quit":
        client_socket.close() # Close connection.
        top.quit() # Close GUI.


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("!quit") # Quit signal for server.
    send() # Send quit signal.
    

"""-------- GUI --------"""
top = tkinter.Tk()
top.title("Chatter - Argon2 secured")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()
my_msg.set("")
scrollbar = tkinter.Scrollbar(messages_frame)
msg_list = tkinter.Listbox(messages_frame, height=20, width=60, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)


"""-------- Terminal --------"""
HOST = input('Enter host: ')
PORT = input('Enter port: ')
if not PORT:
    PORT = 33000
else:
    PORT = int(PORT)

"""-------- Network --------"""
BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)
receive_thread = Thread(target=receive)

"""-------- Start --------"""
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.
