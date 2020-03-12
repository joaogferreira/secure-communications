import asyncio
import json
import argparse
import coloredlogs, logging
import re
import sys, base64, getpass, os
from aio_tcpserver import tcp_server
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, load_pem_parameters, PublicFormat, load_pem_public_key

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_TO_CIPHER = 2
STATE_DIFFIE_PARAMETERS = 3
STATE_KEY = 4
STATE_SECRET = 5
STATE_DATA = 6
STATE_CLOSE = 7

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ''
		self.peername = ''
		self.text = b''

	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT


	def data_received(self, data: bytes) -> None:
		"""
        Called when data is received from the client.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
		logger.debug('Received: {}'.format(data))
		try:
			self.buffer += data.decode()
		except:
			logger.exception('Could not decode data from client')

		idx = self.buffer.find('\r\n')

		while idx >= 0:  # While there are separators
			frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
			self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

			self.on_frame(frame)  # Process the frame
			idx = self.buffer.find('\r\n')

		if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning('Buffer to large')
			self.buffer = ''
			self.transport.close()


	def on_frame(self, frame: str) -> None:
		"""
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
		#logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()

		if mtype == 'OPEN':
			ret = self.process_open(message)
		elif mtype == 'TO_CIPHER':
			ret = self.process_cipher(message)
			logger.info("Ciphersuite has been received.")
		elif mtype == "DIFFIE_PARAMETERS":
			ret = self.process_diffie_parameters(message)
			logger.info("Diffe-Hellman has been received.")
		elif mtype == "KEYS":
			ret = self.process_keys(message)
			logger.info("Public Key has been sent.")
		elif mtype == "SECRET":
			ret = self.process_secret(message)
			logger.info("Building secret...")
		elif mtype == "IV & MAC":
			ret = self.process_iv_mac(message)
			logger.info("IV & MAC have been received.")
		elif mtype == 'DATA':
			ret = self.process_data(message)
		elif mtype == 'CLOSE':
			self.decrypt()
			ret = self.process_close(message)
			logger.info("Done.")
		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()


	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		self._send({'type': 'OK'})

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True

	def process_cipher(self, message: str) -> bool:
		logger.debug("Process Cipher: {}".format(message))

		if self.state == STATE_OPEN:
			# First Packet
			data = base64.b64decode(message['data']).decode("utf-8").split("-")
			self.cipher = data[0]
			self.mode = data[1]
			self.sintese = data[2]
			self.state = STATE_TO_CIPHER

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		self._send({'type':'OK'})
		return True

	def	process_diffie_parameters(self, message: str) -> bool:
		logger.debug("Process Diffie-Hellman Parameters: {}".format(message))

		if self.state == STATE_TO_CIPHER:
			data = base64.b64decode(message.get('data', "").encode())
			self.diffie_parameters = load_pem_parameters(data, backend=default_backend())
			self.state = STATE_DIFFIE_PARAMETERS

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		self._send({'type':'OK'})
		return True
	
	def process_keys(self, message: str) -> bool:
		logger.debug("Process Keys: {}".format(message))

		if self.state == STATE_DIFFIE_PARAMETERS:
			self.pub_key_client = base64.b64decode(message.get('data', "").encode())
			logger.info("Client Public Key has been received.")
			self.priv_key_server = self.diffie_parameters.generate_private_key()
			pub_key_server = self.priv_key_server.public_key()
			pub_key_server_to_bytes = pub_key_server.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
			self.state = STATE_KEY
			

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		message = {'type': 'OK', 'data': base64.b64encode(pub_key_server_to_bytes).decode()}
		self._send(message)
		return True
	
	def process_secret(self, message: str) -> bool:
		logger.debug("Process Secret: {}".format(message))

		if self.state == STATE_KEY:
			load_client_pub_key = load_pem_public_key(self.pub_key_client, backend=default_backend())
			secret = self.priv_key_server.exchange(load_client_pub_key)

			if (self.sintese == "SHA512"):
				sintese = hashes.SHA512()
			else:
				sintese = hashes.SHA256()
			
			if ("CHACHA20" in self.cipher):
				size = int(int(self.cipher.split("CHACHA20")[1])/8)
			else:
				size = int(int(self.cipher.split("AES")[1])/8)

			kdf = HKDF(algorithm=sintese, length=size, salt=None, info=b'handshake data', backend=default_backend())
			self.key = kdf.derive(secret)	
			self.state = STATE_SECRET
		else:
			logger.warning("Invalid state. Discarding")
			return False

		self._send({'type':'OK'})
		return True

	def process_iv_mac(self, message: str) -> bool:
		logger.debug("Process IV & MAC: {}".format(message))

		if self.state == STATE_SECRET:
			data = base64.b64decode(message['data'])
			if "AES" in self.cipher and self.mode == "CBC":
				self.iv = data[:16]
				self.mac = data[16:]
			elif "AES" in self.cipher and self.mode == "GCM": 
				self.iv = data[:12]
				self.mac = data[12:]
			else:
				self.iv = data[:16]
				self.mac = data[16:]
			
		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False
		
		self._send({'type':'OK'})
		return True

	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_SECRET:
			self.state = STATE_DATA
			

		elif self.state == STATE_DATA:
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
			self.text += base64.b64decode(message['data'].encode())
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True

	def decrypt(self):
		if not self.check_mac(self.text):
			logger.warning("Message integrity violated. Discarding")
			return False

		if "CHACHA20" in self.cipher:
			algorithm = algorithms.ChaCha20(self.key, self.iv)
			c = Cipher(algorithm, mode=None,backend=default_backend())
			self.chacha_decrypt(self.text, c)
		
		if "AES" in self.cipher:
			if self.mode == 'GCM':
				c = Cipher( algorithms.AES(self.key), modes.GCM(self.iv), backend=default_backend())
			elif self.mode == 'CBC':
				c = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
			self.aes_decrypt(self.text, c)

	def check_mac(self, text):
		if (self.sintese == "SHA512"):
			algorithm = hashes.SHA512()
		else:
			algorithm = hashes.SHA256()
		m = hmac.HMAC(self.key, algorithm, backend=default_backend())
		m.update(text)
		
		try:
			m.verify(self.mac)
			return True
		except:
			return False

	def chacha_decrypt(self, message, cipher):
		to_write = open('done.txt', 'w')
		decryptor = cipher.decryptor()
		dc = decryptor.update(message)
		to_write.write(dc.decode()) 
		to_write.close()
	
	def aes_decrypt(self, message, cipher):
		to_write = open('done.txt', 'w')
		decryptor = cipher.decryptor()
		
		if self.mode == 'GCM':
			dc = decryptor.update(message)

		elif self.mode == 'CBC':
			dc = decryptor.update(message) + decryptor.finalize()
			unpadder = padding.PKCS7(128).unpadder()
			dc = unpadder.update(dc) + unpadder.finalize()	
			
		to_write.write(dc.decode()) 
		to_write.close()
	

	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE

		return True


	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.debug("Send: {}".format(message))

		message_b = (json.dumps(message) + '\r\n').encode()
		self.transport.write(message_b)

def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()


