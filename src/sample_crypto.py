from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding

# Load the public/private key pairs generated above
public_key = ...
private_key = ...

# Encrypt the message using the public key
message = b'The secret message no one should read'
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypting the message (=cyphertext) using your private key
decrypted_message = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Printing the original and decrypted secret message
print(f'Original message: {message}')
print(f'Decrypted message: {decrypted_message}')