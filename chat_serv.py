#!/usr/bin/env python3
"""Server for Argon2 encrypted, multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import nacl.utils
import nacl.secret 
from nacl.public import PrivateKey, SealedBox


privKeyServer = PrivateKey.generate() # Generate server private key.
unseal_box = SealedBox(privKeyServer) # Create sealed box with private key, needed to decrypt messages encrypted with public key.
pubKeyServer = privKeyServer.public_key # Generate server public key.
clients = {} # Global variable containing clients and their associated properties.


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    
    while True:
        client, client_address = SERVER.accept() # Accept connection request.
        print("%s:%s" % client_address)     
        Thread(target=handle_client, args=(client,)).start() # New thread handeling individual clients.


def handle_client(client):
    """Handles a single client connection."""
    
    client.send(bytes(pubKeyServer)) # Send public key to client.
    secretKey = unseal_box.decrypt(client.recv(BUFSIZ)) # Recieve and decrypt message containing secret key.
    box = nacl.secret.SecretBox(secretKey) # Create secret box with secret key, needed to encrypt and decrypt messages.
    
    #Hybrid Key exchange sucessful.
    
    client.send(box.encrypt(bytes("Hybrid Key exchange sucessful! Type your name and press enter!", "utf8"))) # Send message to client.
    name = box.decrypt(client.recv(BUFSIZ)).decode('utf8') # Recieve and decrypt message containing name, it's a string so it needs utf-8 decoding.
    clients[client] = [name, secretKey] # Save name and secret key to global variable.
    
    #Name recieved.
    
    client.send(box.encrypt(bytes("Welcome %s! If you ever want to quit, type !quit to exit." % name, "utf8"))) # Send message to client.
    broadcast(bytes("%s has joined the chat!" % name, "utf8")) # Send message to everyone, telling 'X' joined the chat.

    while True:
        msg = box.decrypt(client.recv(BUFSIZ)) # Encrypted message recieved and decrypted.
        if msg != bytes("!quit", "utf8"):
            broadcast(bytes(name + ": " + msg.decode('utf8'), 'utf8')) # Send message to everyone.
        else:
            client.send(box.encrypt(bytes("!quit", "utf8"))) # Send encrypted message.
            client.close() # Close connection.
            del clients[client] # Delete client from client list.
            broadcast(bytes("%s has left the chat." % name, "utf8")) # Send message to everyone, telling 'X' left the chat.
            break


def broadcast(msg):
    """Broadcasts a message to all the clients."""
    
    for values in clients.items():
        secretKey = values[1][1] # Get secret key from global variable.
        box = nacl.secret.SecretBox(secretKey) # Create a secret box with secret key, needed to encrypt message.
        msg_encrypted = box.encrypt(msg) # Encrypt message.
        socket = values[0] # Get socket from global variabe.
        socket.send(msg_encrypted) # Send endcrypted message.


"""-------- Network --------"""
HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
