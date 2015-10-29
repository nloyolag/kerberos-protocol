from socket import socket, AF_INET, SOCK_STREAM
import thread
import sys
import pickle
import common
import getpass
import time

# Change timestamps
# User/Password

HOST = ''
PORT = 8888
TGS_IP = '10.25.76.86'
SS_IP = ''

user_credentials = dict([('user', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8')])

def check_password(clear_password, password_hash):
	return common.SHA256.new(clear_password).hexdigest() == password_hash

def tgs_connection(connection):
	""" Communication with TGS """
	# Client sends cleartext message with the user id requesting services
	connection.send('user')
	# Receive Client/TGS Session key encrypted using the secret key of the client
	message_a = session.recv(4096)
	# Receive Ticket-Granting-Ticket encrypted using the key of the TGS
	message_b = session.recv(4096)
	# Decrypt session key with secret key of client
	decrypted_message_a = common.decrypt_aes(message_a, user_credentials[user])
	session_key = decrypted_message_a.session_key
	# Message C composed with TGT and ID of requested service
	message_c = common.MessageC(message_b, 'service')
	# Message D authenticator with id and timestamp
	timestamp = time.time
	message_d = common.MessageD('user', timestamp)
	encrypted_message_d = encrypt_aes(message_d, session_key)
	# Send message c and d
	connection.send(message_c)
	connection.send(encrypted_message_d)
	# Receive messages e and f from TGS
	message_e = session.recv(4096)
	message_f = session.recv(4096)

	messages = [message_e, message_f]
	return messages

def ss_connection(connection, message_e, message_f):
	""" Communication with SS """
	# Client connects to the SS and sends message e encrypted with service's key and g encrypted using session key
	connection.sendall(message_e)
	timestamp = time.time
	message_g = common.MessageD('user', timestamp)
	encrypted_message_g = encrypt_aes(message_g, session_key)
	# Receives message h to confirm identity
	connection.listen(10)
	encrypted_message_h = client.recv(4096)
	# Decrypt confirmation and check timestamp
	message_h = decrypt_aes(encrypted_message_h, session_key)
	# Server provides service

if __name__ == "__main__":
	#user = raw_input('Username: ')
	#password = getpass.getpass('Password: ')
	#if check_password(password, user_credentials[user]):
	print 'Login successful'
	
	socket = socket(AF_INET, SOCK_STREAM)
	print 'Socket created'
	try:
		socket.bind((HOST, PORT))
	except socket.error, msg:
		print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
		sys.exit()
	print 'Bind complete'
	messages = tgs_connection(socket)
	message_e = messages[0]
	message_f = messages[1]
	socket.bind((HOST, PORT))
	ss_connection(socket, message_e, message_f)
	socket.close()
	#else:
	#	print('Invalid credentials')