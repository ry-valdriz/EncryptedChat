# import cryptography
# from cryptography import Fernet
import Crypto, json
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


def encryptMessage(publicKeyAddress, message): #encryption function
    publicKey = RSA.generate(2048) #generate rsa key object

    #create file object for public key
    #publicKeyFile = open('C:\Users\valdr\duodolo-app\public.pem', 'r')
    publicKeyFile = open(publicKeyAddress, 'rb')

    #print('contents of public key: ' + '\n', publicKeyFile.read())

    publicKey = RSA.import_key(publicKeyFile.read()) #create rsa public key object

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

    #iv = b64encode(cipher_AES.iv).decode('utf-8') #conver iv from bytes to string

    cipherText = b64encode(cipherText_Message_Bytes).decode('utf-8') #convert cipher text from bytes to string

    JSON_output = json.dumps({'AES_ciphertext' : cipherText, 'RSA_ciphertext' : cipherText_Keys_String, 'HMAC_Tag' : h.hexdigest() }) 

    #print(JSON_output)
    outfile = open("Testing.encrypt", "w")
    outfile.write(JSON_output)
    outfile.close()

    return JSON_output #return json object containing encrypted keys, ciphertexts, and HMAC tag
    

def decryptMessage(privateKeyAddress, JSON_output):
    
    privateKey = RSA.generate(2048) #generate rsa key object
    jsonFile = json.loads(JSON_output)
    AES_ciphertext = jsonFile['AES_ciphertext']
    RSA_ciphertext = jsonFile['RSA_ciphertext']
    HMAC_tag = jsonFile['HMAC_Tag']

    privateKeyFile = open(privateKeyAddress, 'rb')
    privateKey = RSA.import_key(privateKeyFile.read()) #create rsa private key object

    cipher_rsa = PKCS1_OAEP.new(privateKey) #create rsa cipher object
    keys_plaintext = cipher_rsa.decrypt(RSA_ciphertext)
    AES_key = keys_plaintext[0:255]
    print(AES_key)

    #print(AES_ciphertext)


    return


#MAIN FUNCTION
publicKeyAddress = input('Please enter the address of your public key: ')
message = input('Please enter message to encrypt:')

JSON_output = encryptMessage(publicKeyAddress, message)

privateKeyAddress = input('Please enter the address of your private key: ')

decryptMessage(privateKeyAddress, JSON_output)









