import socket
import thread
import sys
import pickle
import common
import time

#user:password
database = dict([('user', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'), ('service',''),('tgs','')])
CLIENT_TGS_SESSION = '1234123412341234'
CLIENT_SERVICE_SESSION = '1234123412341234'
HOST = ""
PORT = 8888


def connection_thread(connection):
	#Set private key of service server
	print database
	database['service'] = common.sha256_hash('1234123412341234')
	#set private key of tgs
	database['tgs'] = common.sha256_hash('1234123412341234')
	#lifetime for messages to be valid
	lifetime = 3600
    #Receive client ID
	client_ID = connection.recv(4096)
    #Get hashed password from database
	client_secretK = database[client_ID]
	message_a = common.MessageA(CLIENT_TGS_SESSION)
	message_a = common.encrypt_aes(message_a,client_secretK)
	#Set message B with TGT= clientID, ip address, lifetime, client/TGS sessionkey encrypted with secret TGS
	message_b = common.MessageB(client_ID,lifetime,CLIENT_TGS_SESSION)
	message_b = common.encrypt_aes(message_b,common.database['tgs'])
	#Send message A and B to client
	connection.send(message_a)
	connection.send(message_b)
	#receive message C with message B(TGT) and service id
	message_c = connection.recv(4096)
	#receive message D with authenticator(clientID,timestamp) encrypted with client/TGT session key
	message_d = connection.recv(4096)
	#Re serialize object from stream only C because it is not encrypted
	message_c = pickle.loads(message_c)
	#message_d = pickle.loads(message_d) decrypt_aes does this
	#open message C to get message B and service id
	message_b = common.decrypt_aes(message_c.ticket)
	message_b = common.MessageB(message_b.clientId,message_b.validityPeriod,message_b.clientSessionKey)
	message_b = common.decrypt_aes(message_b,database['tgs'])
	#Decrypt message D with with client/TGS session key
	message_d = common.decrypt_aes(message_d,message_b.clientSessionKey)
	#Check validity period of message D.timestamp with B.lifetime
	if message_d.timestamp+message_b.validityPeriod > time.time():
	    #Create message E(client/server ticket(clientID,clientIP,lifetime,client/TGS session key)) encrypted with service sercret key
	    message_e = common.MessageB(client_ID,lifetime,CLIENT_SERVICE_SESSION)
	    message_e = common.encrypt_aes(message_e,database['service'])
	    #Create message F(client/server session key) encrypted with client/tgs session key
	    message_f = common.MessageF(CLIENT_SERVICE_SESSION)
	    message_f = common.encrypt_aes(message_f,message_b.clientSessionKey)
	    #Send message E
	    connection.send(message_e)
	    connection.send(message_f)
	else:
		print "Validity period of message D is not valid."


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