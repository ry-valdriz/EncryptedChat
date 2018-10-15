# import cryptography
# from cryptography import Fernet
import Crypto, json
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

publicKey = RSA.generate(2048) #generate rsa key object

publicKeyAddress = input('Please type address of your public key: ')

#create file object for public key
#publicKeyFile = open('C:\Users\valdr\duodolo-app\public.pem', 'r')
publicKeyFile = open(publicKeyAddress, 'rb')

#print('contents of public key: ' + '\n', publicKeyFile.read())

publicKey = RSA.import_key(publicKeyFile.read()) #create rsa public key object

message = input('Please enter message to encrypt:')

message = message.encode('utf-8')#convert to bytes to use in AES encryption function

cipher_rsa = PKCS1_OAEP.new(publicKey) #create rsa cipher object

key_AES = get_random_bytes(32) #generate 256 bit key for AES

cipher_AES = AES.new(key_AES, AES.MODE_CBC) #initialize AES object

cipherText_Message_Bytes = cipher_AES.encrypt(pad(message, 128)) #encrypt message

key_HMAC = get_random_bytes(32) 

h = HMAC.new(key_HMAC, digestmod=SHA256) #instantiate hmac object

h.update(message) #authenticate the message

print('HMAC tag: ', h.hexdigest()) #print out hmac tag of the authenticated message

# keys_bytearray = bytearray(key_AES) #copy aes key to bytearray
# keys_bytearray.append(key_HMAC) #append hmac key to keys_bytearray
ka = b64encode(key_AES).decode('utf-8') #string of aes key
print('AES Key: ', ka)
kh = b64encode(key_HMAC).decode('utf-8') #string of hmac key
print('HMAC Key: ',kh)
k = ka + kh #concatenate the two keys
print('Concatenated Keys:', k) #test

keys_bytes = k.encode('utf-8') #convert back to bytes

cipherText_Keys_Bytes = cipher_rsa.encrypt(keys_bytes) #encrypt AES and HMAC keys with rsa encryption
cipherText_Keys_String = b64encode(cipherText_Keys_Bytes).decode('utf-8')

print('Encrypted keys:' , cipherText_Keys_String ) #print out AES and HMAC keys concatenated and encrypted

iv = b64encode(cipher_AES.iv).decode('utf-8') #conver iv from bytes to string

cipherText = b64encode(cipherText_Message_Bytes).decode('utf-8') #convert cipher text from bytes to string

output = json.dumps({'AES ciphertext' : cipherText, 'RSA cipher text' : cipherText_Keys_String, 'HMAC Tag' : h.hexdigest() }) 

print(output)










