import socket
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
AUTH_IP = '10.25.76.2'

user_credentials = dict([('user', common.sha256_hash('1234123412341234').hexdigest()[0:16])])
#user_credentials['user'] = common.sha256_hash('1234123412341234').hexdigest()[0:16]

def check_password(clear_password, password_hash):
	return common.SHA256.new(clear_password).hexdigest() == password_hash

def tgs_connection(connection):
	# Client sends cleartext message with the user id requesting services
	connection.connect((AUTH_IP, PORT))
	print 'Connected successfully to ip ' + AUTH_IP
	connection.sendall('user')
	# Receive Client/TGS Session key encrypted using the secret key of the client
	message_a = connection.recv(4096)
	# Receive Ticket-Granting-Ticket encrypted using the key of the TGS
	message_b = connection.recv(4096)
	# Decrypt session key with secret key of client
	decrypted_message_a = common.decrypt_aes(message_a, user_credentials['user'])
	session_key = decrypted_message_a.sessionKey
	# Message C composed with TGT and ID of requested service
	message_c = common.MessageC(message_b, 'service')
	# Message D authenticator with id and timestamp
	timestamp = time.time
	message_d = common.MessageD('user', timestamp)
	encrypted_message_d = common.encrypt_aes(message_d, session_key)
	# Send message c and d
	message_c = pickle.dumps(message_c)
	connection.sendall(message_c)
	connection.sendall(encrypted_message_d)
	# Receive messages e and f from TGS
	message_e = connection.recv(4096)
	message_f = connection.recv(4096)

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
	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	"""try:
		s.bind((HOST, PORT))
	except socket.error:
		print 'Socket bind error'
		sys.exit()
	print 'Bind complete'"""

	messages = tgs_connection(s)
	message_e = messages[0]
	message_f = messages[1]
	s.bind((HOST, PORT))
	ss_connection(s, message_e, message_f)
	s.close()
	#else:
	#	print('Invalid credentials')