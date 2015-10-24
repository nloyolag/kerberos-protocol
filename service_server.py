import socket
import common

HOST = ''
PORT = 8888

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(10)

while True:
    # Wait for connection from client
    connection, address = s.accept()

    # Receive 2 messages:
    #     Message E: Client to server ticket encryted with services secret key
    #     Message G: New authenticator(clientID, Timestamp) encrypted with session key
    me = connection.recv(4096)
    mg = connection.recv(4096)

# Decrypt ticket with SS secret key to retrieve session key
# Decrypt authenticator with session key
# Send message to Client
#     Message H: Timestamp in clients authenticator encrypted with session key
#
# Wait for requests from Client
