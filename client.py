import socket
import thread
import sys
import pickle
import common
import getpass

# Credentials for user to login

HOST = ''
PORT = 8888
#PRIVATE_KEY = '1234'
#SESSION_KEY = '1234'

user_credentials = dict([('user', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8')])

def check_password(clear_password, password_hash):
	return SHA256.new(clear_password).hexdigest() == password_hash

def connection(connection):
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


if __name__ == "__main__":
	user = raw_input('Username: ')
	password = getpass.getpass('Password: ')
	if check_password(password, user_credentials[user]):
		print('Login successful')
		

	else:
		print('Invalid credentials')