import asyncio
import json
import argparse
import random
import coloredlogs, logging
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

ALGORITHMS = ["AES128-GCM", "AES128-CBC", "AES192-GCM", "AES192-CBC", "AES256-GCM", "AES256-CBC"]
SYNTHESIS = ["SHA256", "SHA512"]

class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """
    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """
        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = '' # Buffer to receive data chunks

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport
        logger.debug('Connected to Server')
        
        message = {'type': 'OPEN', 'file_name': self.file_name}
        
        self._send(message)
        self.state = STATE_OPEN

    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
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
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'OK':  # Server replied OK. We can advance the state
            
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.pick_cipher()
                logger.info("Ciphersuite has been sent.")
                self.state = STATE_TO_CIPHER
            
            elif self.state == STATE_TO_CIPHER:
                self.pick_diffie_parameters() 
                logger.info("Diffie-Hellman Parameters have been sent.")
                self.state = STATE_DIFFIE_PARAMETERS
            
            elif self.state == STATE_DIFFIE_PARAMETERS:
                self.build_keys() 
                logger.info("Public key has been sent.")
                self.state = STATE_KEY
            
            elif self.state == STATE_KEY:
                self.pub_key_server = base64.b64decode(message.get('data', "").encode())
                logger.info("Server Public Key has been received.")
                self._send({'type':'SECRET'})
                self.state = STATE_SECRET
            
            elif self.state == STATE_SECRET:
                self.pick_secret()
                self.encrypt()
                self.state = STATE_DATA
            
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                self.send_file('encrypt.txt')
            
            else:
                logger.warning("Ignoring message from server")
            
            return

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()
    
    def pick_cipher(self) -> None:
        pick = random.choice(ALGORITHMS)
        
        self.cipher, self.mode = pick.split("-")[0], pick.split("-")[1]
        
        self.sintese = random.choice(SYNTHESIS)
    
        ciphersuite = (self.cipher + "-" + self.mode + "-" + self.sintese).encode()

        msg = {'type': 'TO_CIPHER', 'data': base64.b64encode(ciphersuite).decode()}
        self._send(msg)

    def pick_diffie_parameters(self) -> None:
        self.diffie = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
        diffie_pem = self.diffie.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
        
        msg = {'type': 'DIFFIE_PARAMETERS', 'data': base64.b64encode(diffie_pem).decode()}
        self._send(msg)
    
    def build_keys(self) -> None:
        self.priv_key_client = self.diffie.generate_private_key()
        pub_key_client = self.priv_key_client.public_key()
        pub_key_to_bytes = pub_key_client.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        
        msg = {'type': 'KEYS', 'data':  base64.b64encode(pub_key_to_bytes).decode()}
        self._send(msg)
    
    def pick_secret(self) -> None:
        load_server_pub_key = load_pem_public_key(self.pub_key_server, backend=default_backend())
        secret = self.priv_key_client.exchange(load_server_pub_key)
        
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

    def encrypt(self) -> None:
        to_encrypt = open(self.file_name, 'rb').read()
        
        if "CHACHA20" in self.cipher:
            self.iv = os.urandom(16)
            algorithm = algorithms.ChaCha20(self.key, self.iv)
            c = Cipher(algorithm, mode=None, backend=default_backend())
            text = self.chacha_encrypt(to_encrypt, c)
        
        elif "AES" in self.cipher and self.mode == 'GCM':
            self.iv = os.urandom(12)
            c = Cipher(algorithms.AES(self.key), modes.GCM(self.iv),backend=default_backend())
            text = self.aes_encrypt(to_encrypt, c)
        
        elif "AES" in self.cipher and self.mode == 'CBC':
            self.iv = os.urandom(16)
            c = Cipher(algorithms.AES(self.key), modes.CBC(self.iv),backend=default_backend())
            text = self.aes_encrypt(to_encrypt, c)

        mac = self.generate_mac(text)
        message = {'type':'IV & MAC', 'data': base64.b64encode(self.iv + mac).decode()}
        self._send(message)
    
    def chacha_encrypt(self, message, cipher):
        to_write = open('encrypt.txt', 'wb')
        encryptor = cipher.encryptor()
        c = encryptor.update(message)
        
        to_write.write(c)
        return c

    def aes_encrypt(self, message, cipher):
        to_write = open('encrypt.txt', 'wb')
        encryptor = cipher.encryptor()
        if self.mode == 'GCM':
            c = encryptor.update(message)      
        else:
            c = encryptor.update(self.padding_text(message)) + encryptor.finalize()
            
        to_write.write(c)
        return c

    def padding_text (self, text):
        padder = padding.PKCS7(128).padder()
        data = padder.update(text)
        data += padder.finalize()

        return data
    
    def generate_mac(self, text):
        if (self.sintese == "SHA512"):
            algorithm = hashes.SHA512()
        else:
            algorithm = hashes.SHA256()
        
        h_mac = hmac.HMAC(self.key, algorithm, backend=default_backend())
        h_mac.update(text)
        
        return h_mac.finalize()

 
    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

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
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()