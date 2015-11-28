import socket
import thread
import sys
import pickle
import common

HOST = ''
PORT = 8889
PRIVATE_KEY = common.sha256_hash('1234123412341234').hexdigest()[0:16]

# Function executed for each client attempting to connect
def connection_thread(connection):
    # Receive 2 messages:
    #     Message E: Client to server ticket encryted with services secret key
    #     Message G: New authenticator(clientID, Timestamp) encrypted with session key
    message_e = connection.recv(4096)
    message_g = connection.recv(4096)

    # Decrypt ticket with SS secret key to retrieve session key
    ticket = common.decrypt_aes(message_e, PRIVATE_KEY)
    # Decrypt authenticator with session key
    authenticator = common.decrypt_aes(message_g, ticket.clientSessionKey)

    # Send message to Client
    #     Message H: Timestamp in clients authenticator encrypted with session key
    message_h = common.MessageH(authenticator.timestamp)
    message_h = common.encrypt_aes(message_h, ticket.clientSessionKey)
    connection.sendall(message_h)

    # Wait for requests from Client
    data = connection.recv(4096)
    reply = 'Received ' + data
    print reply
    connection.close()


if __name__ == "__main__":

    # Creation of socket for connection with client
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.bind((HOST, PORT))
    except socket.error:
        print 'Socket Bind Error'
        sys.exit()

    # Wait for connections from client
    s.listen(10)

    while True:
        connection, address = s.accept()
        print "New connection with " + address[0] + ':' + str(address[1])
        thread.start_new_thread(connection_thread, (connection,))

    s.close()
