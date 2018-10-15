# import cryptography
# from cryptography import Fernet
import Crypto, json
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

publicKey = RSA.generate(2048) #generate rsa key object

publicKeyAddress = input('Please type address of your public key: ')

#create file object for public key
#publicKeyFile = open('C:\Users\valdr\duodolo-app\public.pem', 'r')
publicKeyFile = open(publicKeyAddress, 'rb')

#print('contents of public key: ' + '\n', publicKeyFile.read())

publicKey = RSA.import_key(publicKeyFile.read()) #create rsa public key object

message = input('Please enter message to encrypt:')

message = message.encode('utf-8')

cipher_rsa = PKCS1_OAEP.new(publicKey) #create rsa cipher object

key_AES = get_random_bytes(32) #generate 256 bit key for AES

cipher_AES = AES.new(key_AES, AES.MODE_CBC) #initialize AES object

cipherTextBytes = cipher_AES.encrypt(pad(message, 128)) 

iv = b64encode(cipher_AES.iv).decode('utf-8') 

cipherText = b64encode(cipherTextBytes).decode('utf-8')

output = json.dumps({'iv' : iv, 'ciphertext' : cipherText}) #encrypted message

print(output)










