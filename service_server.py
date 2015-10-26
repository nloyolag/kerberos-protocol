import socket
import thread
import sys
import common

HOST = ''
PORT = 8888
PRIVATE_KEY = '1234123412341234'
SESSION_KEY = '1234123412341234'

# Function executed for each client attempting to connect
def connection_thread(connection):
    connection.send("Connection Established. Waiting for message E and G...\n")

    # Receive 2 messages:
    #     Message E: Client to server ticket encryted with services secret key
    #     Message G: New authenticator(clientID, Timestamp) encrypted with session key
    message_e = connection.recv(4096)
    message_g = connection.recv(4096)

    message_e = pickle.loads(message_e)
    message_g = pickle.loads(message_g)

    # Decrypt ticket with SS secret key to retrieve session key
    ticket = common.decrypt_aes(message_e, PRIVATE_KEY)

    # Decrypt authenticator with session key
    authenticator = common.decrypt_aes(message_g, PRIVATE_KEY)

    # Send message to Client
    #     Message H: Timestamp in clients authenticator encrypted with session key
    message_h = common.MessageH(timestamp)
    message_h = common.encrypt_aes(message_h, SESSION_KEY)
    message_h = pickle.dumps(message_h)
    connection.sendall(message_h)

    # Wait for requests from Client
    while True:
        data = conn.recv(4096)
        reply = 'Received ' + data
        if not data:
            break

        connection.sendall(reply)

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
