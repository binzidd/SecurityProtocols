import os
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA


def sign_file(f):

    # Master will sign all the data to be uploaded with his private key
    # Generate the private key
    private_key_master = open("private_key.pem").read()
    # Hash the file
    hashed_file = SHA256.new(f)
    #import the private key into RSA_new_keys
    RSA_new_keys=RSA.importKey(private_key_master)
    # Signing
    signer = PKCS1_PSS.new(RSA_new_keys)
    master_sign = signer.sign(hashed_file)
    # Both signature and data sent
    sending_payload = master_sign + f
    return sending_payload



if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
