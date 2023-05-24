import binascii
import json
import socket
import threading
import time

from blockchain import *
from network import *

import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from cryptography.hazmat.primitives import serialization

def make_transaction(message: str, private_key: ed25519.Ed25519PrivateKey, nonce: int):
	transaction = {}
	transaction["message"] = message
	transaction["nonce"] = nonce
	transaction["signature"] = private_key
	return transaction

class RemoteNode():
	def __init__(self, host: str, port: int) -> None:
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((host, port))
		self.private_key = ed25519.Ed25519PrivateKey.generate()
		self.public_key = self.private_key.public_key()

	def transaction(self, transaction: dict):
		'''
		Send transaction request to connected node
		'''
		# Get hex representation of 'sender' for convenient communication
		public_key_bytes = self.public_key.public_bytes(
			encoding=serialization.Encoding.Raw,
			format=serialization.PublicFormat.Raw
		)
		public_key_hex = binascii.hexlify(public_key_bytes).decode()
		transaction['sender'] = public_key_hex

		# Get hex representation of 'signature' for convenient communication
		if type(transaction['signature']) != str:
			signature_bytes = transaction['signature'].private_bytes(
				encoding=serialization.Encoding.Raw,
				format=serialization.PrivateFormat.Raw,
				encryption_algorithm=serialization.NoEncryption()
			)
			signature_hex = binascii.hexlify(signature_bytes).decode()
			transaction['signature'] = signature_hex
		
		# Reject invalid transactions
		transaction_valid = validate_transaction(transaction) 
		if not transaction_valid:
			print("Error in transaction(): 'transaction' dict is in incorrect format")
		# Parse valid transaction to JSON string and send through socket
		else:
			msg = {
				'type': "transaction",
				'payload': transaction
			}
			try:
				msg_json = json.dumps(msg)
				send_prefixed(self.sock, msg_json.encode())
				response = recv_prefixed(self.sock)	# Get outcome
				return bool(response.decode()) 
			except Exception as e:
				print("Error in transaction(): {}", e)
		return False
	
	def values(self, idx: int):
		'''
		Send 'values' request to connected node
		Recieve 'values' response from connected node
		'''
		# 1. Send
		msg = {
			'type': "values",
			'payload': idx
		}
		try:
			msg_json = json.dumps(msg)
			send_prefixed(self.sock, msg_json.encode())
		except Exception as e:
			print("Error in sending values(): {}", e)
		
		# 2. Receive
		self.sock.settimeout(5) 
		try:
			response = recv_prefixed(self.sock)
			values = json.loads(response.decode())
			return values
		except (socket.timeout, TimeoutError, RuntimeError) as e:
			print("Error in recieving values(): {}", e)
			return []

class ServerRunner():
	def __init__(self, host: str, port: int, f: int) -> None:
		self.blockchain = Blockchain()
		self.host = host
		self.port = port
		self.sock = sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connections = []
		self.f_max = f
		self.f_curr = 0

		self.round_num = 2
		self.curr_values = []

		self.lock = threading.Lock()

	def append(self, remote_node: RemoteNode):
		self.connections.append(remote_node)

	def broadcast(self, neighbour: RemoteNode):
		'''
		Send curr_values to all neighbours &
		Append neighbours' proposed blocks to curr_values
		'''
		new_values = neighbour.values(self.round_num)
		for block in new_values:
				self.curr_values.append(block)
	
	def consensus_protocol(self):
		'''
		  Reach consensus on which block should be added
			Propogate decided block to all neighbours
		'''
		# Crash Tolerance
		if (len(self.curr_values) < 2 * self.f_max+1): # +1 to account for 'block_to_propose'
			self.stop()

		# 1. Reach concensus on which block to append
		non_empty = []
		for block in self.curr_values:
			if block['transactions'] and block['index'] == self.round_num:
				non_empty.append(block)
		if len(non_empty) > 0:
			decided_block = min(non_empty, key=lambda x: x['current_hash'])
		else:
			return

		# 2. Append the decided block to the blockchain
		self.blockchain.new_block(decided_block)
		print("Decided block on port {}: {}".format(self.port, decided_block))
		print("")

		# Refresh values for next communication round
		self.curr_values = []
		self.round_num += 1
	
	
	def wait(self, conn, temp_blockchain, transaction=None):
		'''
		Listen for 2.5 seconds for new transactions to append
		'''
		nonces = [] # Ensure there are no duplicate nonces
		if transaction:
			nonces = [transaction['nonce']]

		# Listening...
		conn.settimeout(0.1)
		start_time = time.time()
		while time.time() - start_time < 2.4:
			try:
				request = recv_prefixed(conn)
				request_dict = json.loads(request.decode())

				# Add up to 3 transactions if received within 2.5 seconds
				if request_dict['type'] == "transaction":
					transaction = request_dict['payload']
					if transaction['nonce'] not in nonces:
						response = temp_blockchain.add_transaction(transaction)
						nonces.append(transaction['nonce'])
					else:
						response = False
					send_prefixed(conn, str(response).encode())

			except socket.timeout:
				continue
		conn.settimeout(5)

		# Either new block to propose or empty block
		temp_blockchain.new_block() 
		block_to_propose = temp_blockchain.last_block()

		self.curr_values.append(block_to_propose)
		if block_to_propose['transactions']:
			print("New block created on port {}: {}\n".format(self.port, block_to_propose))
			self.stop()

	def communicate(self, conn: socket.socket):
		'''
		Continuously communicate with client until
		connection is broken or timed out
		'''
		# Listen for new requests
		request = b''
		conn.settimeout(5) 
		while True:
			try:
				request = recv_prefixed(conn)
			except socket.timeout and TimeoutError:  # 1st timeout -> try 1 more time
				try:
					request = recv_prefixed(conn)
				except socket.timeout and TimeoutError:  # 2nd timeout -> close connection
					with self.lock:
						conn.close()
						self.f_curr += 1
						if self.f_curr > self.f_max:
							print("Maximum number of tolerated failures exceeded: Shutting down server")
							self.stop()
						return
			request_dict = json.loads(request.decode())

			# 1. 'transaction' 
			if request_dict['type'] == "transaction":
				transaction = request_dict['payload']

				temp_blockchain = Blockchain() # Create block to propose with incoming transactions
				response = temp_blockchain.add_transaction(transaction)
				print("Port {} received transaction: {}\n".format(self.port, transaction))
				send_prefixed(conn, str(response).encode())
				self.wait(conn, temp_blockchain, transaction) # Listen for additional transactions
				
				# Send and recieve potential new blocks
				for neighbour in self.connections:
					self.broadcast(neighbour)

			# 2. 'values'
			elif request_dict['type'] == "values":
				if request_dict['payload'] == self.round_num:
					temp_blockchain = Blockchain()
					self.wait(conn, temp_blockchain) # Listen for additional transactions
					response = json.dumps(self.curr_values)
					send_prefixed(conn, response.encode())
					
					# Send and recieve potential new blocks
					for neighbour in self.connections:
						self.broadcast(neighbour)
		
			self.consensus_protocol()

	def start(self): # Start Server
		print(f"Starting server on {self.host}:{self.port}")
		self.sock.bind((self.host, self.port))
		self.sock.listen(5)
		while True:
			try:
				conn, addr = self.sock.accept()
			except ConnectionAbortedError:
				break

			com_thread = threading.Thread(target=self.communicate, args=(conn, ))
			com_thread.start()

	def stop(self): # Stop Server
		self.sock.close()