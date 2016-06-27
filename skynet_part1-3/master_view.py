from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os


def decrypt_valuables(f):


    # The encrypted data obtained is first split as RSA and AES blocks
    RSA_data = f[0:512]
    AES_data_encrypt = f[512:]

    # Obtain private key created by OpenSSL
    private_key_master = open("private_key.pem").read()
    RSA_cipher=RSA.importKey(private_key_master)

    # decrypt the RSA block into IV and key
    RSA_decrypt = PKCS1_OAEP.new(RSA_cipher)
    RSA_value = RSA_decrypt.decrypt(RSA_data)


    # Splitting IV and Key here
    RSA_value_IV = RSA_value[:16]
    RSA_value_key = RSA_value[16:32]


    # Obtaining the hash from decrypted RSA
    RSA_hash = RSA_value[32:]
    

    # Creating the Hash from the payload of the IV and Key
    Payload_hash = RSA_value_IV + RSA_value_key
    Hash_generated = SHA256.new(Payload_hash).digest()
    

    # Checking with the hash of received_files to check if the values are intact or not
    if (RSA_hash == Hash_generated):
        print("Key and IV safe")
    else :
        print("Key and IV altered. DO NOT TRUST THE DATA")

    # AES decryption to get the data sent by bot
    AES_cipher = AES.new(RSA_value_key, AES.MODE_CFB, RSA_value_IV)
    data_obtained = AES_cipher.decrypt(AES_data_encrypt)
    print('This is the data sent to master')
    print(data_obtained.decode(encoding='UTF-8'))


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
