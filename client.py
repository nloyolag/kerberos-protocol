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
	session_key = session.recv(4096)
	# Receive Ticket-Granting-Ticket encrypted using the key of the TGS
	ticket_granting_ticket = session.recv(4096)
	# Decrypt session key with secret key of client
	session_key = pickle.loads(session_key)
	session_key = common.decrypt_aes(session_key, user_credentials[user])
	# Send message composed with TGT and ID of requested service
	connection.send(ticket_granting_ticket)

if __name__ == "__main__":
	user = raw_input('Username: ')
	password = getpass.getpass('Password: ')
	if check_password(password, user_credentials[user]):
		print('Login successful')
		

	else:
		print('Invalid credentials')