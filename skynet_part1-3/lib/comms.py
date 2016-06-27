import struct

from Crypto.Cipher import AES
from dh import aes_iv
from Crypto.Hash import SHA256, HMAC
from dh import create_dh_key, calculate_dh_secret


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        #initialising the self connections
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.iv= 0
        self.shared_key = 'temp'
        self.counter = 0
        self.receiver_counter= 0
        self.initiate_session()

    def initiate_session(self):
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_key = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_key))

        aes_key = self.shared_key[:32]
        #shortnening the value of aes_key to match the AES mode requirement
        self.iv = aes_iv()
        self.cipher = AES.new(aes_key, AES.MODE_CFB, self.iv)

    def send(self, data):
        if self.cipher:
            ##Implementing sender counter
            self.counter += 1
            counter_pack = struct.pack('I', self.counter)

            #HMAC IMPLEMENTATION
            hmac_input = HMAC.new(bytes(self.shared_key[:32], "ascii"), data,
                           digestmod=SHA256)  # implementing shared key as the DH key and digest mod as sha 256
            hmac_value = hmac_input.digest()


            ## final_data represents counter || hmac || data
            final_data = counter_pack + hmac_value + data

            encrypted_data = self.cipher.encrypt(final_data) #append all the inputs
            data_sent= encrypted_data+ self.iv

            #Changing IV for a new transfer
            aes_key = self.shared_key[:32]
            self.iv=aes_iv()
            self.cipher=AES.new(aes_key, AES.MODE_CFB, self.iv)


            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))

        else:
             data_sent = data

        #Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(data_sent))
        self.conn.sendall(pkt_len)
        self.conn.sendall(data_sent)

    def recv(self):
        #Decode the data's length from an unsigned two byte int ('H')

        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        #separating IV and DATA
        encrypted_data_withiv = self.conn.recv(pkt_len)
        iv_received = encrypted_data_withiv[-16:]
        encrypted_data = encrypted_data_withiv[:-16]

        if self.cipher:
            ##  data  =  counter || hmac || data
            key = self.shared_key[:32]
            aes_decrypt = AES.new(key, AES.MODE_CFB, iv_received)
            data = aes_decrypt.decrypt(encrypted_data)
            # performing split on data to check decrypt
            data_received = data[36:]
            print('data received is : ' + str(data_received))

            self.receiver_counter += 1
            #unpacking counter
            counter_value= data[:4]
            counter_unpack = struct.unpack('I', counter_value)[0]

            #splitting hmac
            hmac_received = data[4:36]
            hmac_performed = HMAC.new(bytes(self.shared_key[:32], "ascii"), data[36:],
                                   digestmod=SHA256)  # implementing shared key as the DH key and digest mod as sha 256
            value_hmac = hmac_performed.digest()

            if hmac_received == value_hmac:
                print('Data Integrity Maintained : DATA IS INTACT')
            else:
                print('Tampered Data')
            if counter_unpack == self.receiver_counter:
                print('No Replay Attack detected')
            else:
                print('Dont trust this data. its repeated')
                self.conn.close()

        if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data_withiv

        return data

    def close(self):
        self.conn.close()
