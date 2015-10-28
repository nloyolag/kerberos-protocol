import socket
import thread
import sys
import pickle
import common
import getpass

# Change timestamps

HOST = ''
PORT = 8888
#PRIVATE_KEY = '1234'
#SESSION_KEY = '1234'

user_credentials = dict([('user', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8')])

def check_password(clear_password, password_hash):
	return SHA256.new(clear_password).hexdigest() == password_hash

def connection(connection):
	""" Communication with TGS """
	# Client sends cleartext message with the user id requesting services
	connection.send('user')
	# Receive Client/TGS Session key encrypted using the secret key of the client
	message_a = session.recv(4096)
	# Receive Ticket-Granting-Ticket encrypted using the key of the TGS
	message_b = session.recv(4096)
	# Decrypt session key with secret key of client
	message_a = pickle.loads(message_a)
	session_key = common.decrypt_aes(message_a.session_key, user_credentials[user])
	# Message C composed with TGT and ID of requested service
	message_c = common.MessageC(message_b, 'service')
	# Message D authenticator with id and timestamp
	message_d = common.MessageD('user', timestamp)
	encrypted_message_d = encrypt_aes(message_d, session_key)
	# Send message c and d
	connection.send(message_c)
	connection.send(encrypted_message_d)
	# Receive messages e and f from TGS
	message_e = session.recv(4096)
	message_f = session.recv(4096)
	
	ss_connection(connection, message_e, message_f)


def ss_connection(connection, message_e, message_f):
	""" Communication with SS """
	# Client connects to the SS and sends message e encrypted with service's key and g encrypted using session key
	connection.send(message_e)
	message_g = common.MessageG('user', timestamp)
	encrypted_message_g = encrypt_aes(message_g, session_key)
	# Receives message h to confirm identity
	encrypted_message_h = session.recv(4096)
	# Decrypt confirmation and check timestamp
	message_h = decrypt_aes(encrypted_message_h, session_key)
	# Server provides service

if __name__ == "__main__":
	user = raw_input('Username: ')
	password = getpass.getpass('Password: ')
	if check_password(password, user_credentials[user]):
		print('Login successful')
		

	else:
		print('Invalid credentials')