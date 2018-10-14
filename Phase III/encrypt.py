# import cryptography
# from cryptography import Fernet
import Crypto
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

publicKey = RSA.generate(2048) #generate rsa key object

publicKeyAddress = input('Please type address of your public key: ')

#create file object for public key
#publicKeyFile = open('C:\Users\valdr\duodolo-app\public.pem', 'r')
publicKeyFile = open(publicKeyAddress, 'rb')

#print('contents of public key: ' + '\n', publicKeyFile.read())

publicKey = RSA.import_key(publicKeyFile.read())

cipher_rsa = PKCS1_OAEP.new(publicKey)

message = input('Please enter message to encrypt:')

cipherText = cipher_rsa.encrypt(message)

#print('Encrypted Message: ', cipherText )

privateKeyAddress = input('Please enter the address of the private key: ')

privateKey = RSA.import_key(privateKeyAddress.read())

cipher_rsa = PKCS1_OAEP.new(privateKey)

print(cipher_rsa.decrypt(cipherText))


