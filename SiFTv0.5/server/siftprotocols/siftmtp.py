#python3

import socket, sys, getpass
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		self.msg_hdr_ver = b'\x00\x05'
		self.msg_hdr_ver2 = b'\x01\x00'
		self.size_msg_hdr = 6
		self.size_msg_hdr2 = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.msg_hdr_rsv = b'\x00\x00'
		self.size_mac = 12
		self.etk_size = 256
  
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
  
		# --------- VARIABLES ------------
		self.snd_counter = 1
		self.rcv_counter = 0
		self.final_transfer_key = b''
  
		# --------- STATE ------------
		self.peer_socket = peer_socket


	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header_old(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'] = msg_hdr[i:i+self.size_msg_hdr_len]
		return parsed_msg_hdr

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i +self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i +self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i +self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr	

	# receives n bytes from the peer socket, just connection, ignore
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg_old(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# DEBUG, ignore
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		return parsed_msg_hdr['typ'], msg_body

	def load_keypair(self,privkeyfile): # change or no
		# passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
		passphrase = '12345'
		with open(privkeyfile, 'rb') as f:
			keypairstr = f.read()
		try:
			return RSA.import_key(keypairstr, passphrase=passphrase)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Can load key --> ' + e.err_msg)
    
	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr2)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr2: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver2:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		if(parsed_msg_hdr['sqn'] <= self.rcv_counter.to_bytes(2, byteorder='big')):
			raise SiFT_MTP_Error('Replayed or out-of-order message received')


		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		plaintext = b''
		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr2)    
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# server side 
		if parsed_msg_hdr['typ'] == self.type_login_req:
			etk = msg_body[-256:]  # encrypted AES key from the login message
			keypair = self.load_keypair('privkeyfile.pem')
			RSAcipher = PKCS1_OAEP.new(keypair)
   
			try:
				tk = RSAcipher.decrypt(etk)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to decrypt AES key --> ' + e.err_msg)
			nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
			mac = msg_body[-(self.size_mac+ self.etk_size): -self.etk_size]
			epd = msg_body[:-(self.size_mac+ self.etk_size)]
   
			cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=12)
			cipher.update(msg_hdr)
			self.final_transfer_key = tk
   
		else:
			nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
			mac = msg_body[-(self.size_mac):]
			epd = msg_body[:-(self.size_mac)]	
			try:
				cipher = AES.new(self.final_transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
				cipher.update(msg_hdr)

			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Error: Cannot extract fields from message body.')

		try:
			plaintext = cipher.decrypt_and_verify(epd, mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('MAC verification failed--> ' + e.err_msg)

		# DEBUG, ignore
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr2: 
			raise SiFT_MTP_Error('Incomplete message body reveived')
		self.rcv_counter += 1
		return parsed_msg_hdr['typ'], plaintext

	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg_old(self, msg_type, msg_payload):
		
		# build message
		msg_size = self.size_msg_hdr + len(msg_payload)
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len

		# DEBUG, irrelevant
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + msg_payload)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		# build message
		msg_size = self.size_msg_hdr2 + len(msg_payload) + self.size_mac
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr_sqn = self.snd_counter.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		rnd = get_random_bytes(6)      # 6-byte random value for header
		rsv = self.msg_hdr_rsv
  
		msg_hdr = self.msg_hdr_ver2 + msg_type + msg_hdr_len + msg_hdr_sqn + rnd + rsv
		
  
		#Encrypting payload before sending
		nonce = msg_hdr_sqn + rnd              # 8 bytes total (as required by SiFT)
		cipher = AES.new(self.final_transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
		cipher.update(msg_hdr)
		epd, mac = cipher.encrypt_and_digest(msg_payload)
		encrypted_msg_payload = epd + mac

		# DEBUG, irrelevant
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('ENc BDY (' + str(len(encrypted_msg_payload)) + '): ')
			print(encrypted_msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + encrypted_msg_payload)
   			# increment send counter
			self.snd_counter += 1
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
