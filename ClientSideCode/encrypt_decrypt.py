# import cryptography
# from cryptography import Fernet
import Crypto, json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import tkinter as tk

def encryptAES(message, key_AES):
    block_size = 128
    message = message.encode('utf-8')#convert to bytes to use in AES encryption function
    cipher_AES = AES.new(key_AES, AES.MODE_CBC) #initialize AES object
    iv = cipher_AES.iv
    cipherText_Message_Bytes = cipher_AES.encrypt(pad(message, block_size)) #encrypt message
    cipherText_Message_Bytes = iv + cipherText_Message_Bytes #prepend iv
    return cipherText_Message_Bytes

def decryptAES(key_AES, cipherText, iv):
    block_size = 128
    cipher_AES = AES.new(key_AES, AES.MODE_CBC, iv)
    plainText = unpad(cipher_AES.decrypt(cipherText), block_size)
    plainText = plainText.decode('utf-8')
    return plainText

def encryptRSA(publicKeyFile, keys_bytes): #change to PGP
    bits = 2048
    publicKey = RSA.generate(bits) #generate rsa key object
    publicKey = RSA.import_key(publicKeyFile.read()) #create rsa public key object
    cipher_rsa = PKCS1_OAEP.new(publicKey) #create rsa cipher object
    return cipher_rsa.encrypt(keys_bytes)

def decryptRSA(privateKey, RSA_ciphertext):
    cipher_rsa = PKCS1_OAEP.new(privateKey) #create rsa cipher object
    return cipher_rsa.decrypt(RSA_ciphertext)


def createHMAC(key_HMAC):
    return HMAC.new(key_HMAC, digestmod=SHA256) #instantiate hmac object


def encryptMessage(publicKeyAddress, message): #encryption function
    print('Encrypting. . . . . . . . . . . . . . . . . .')
    
    #create file object for public key
    publicKeyFile = open(publicKeyAddress, 'rb')
    
    key_AES = get_random_bytes(32) #generate 256 bit key for AES
    key_HMAC = get_random_bytes(32) #256 bit key for HMAC

    cipherText_Message_Bytes = encryptAES(message, key_AES) #encrypt message with AES
   
    h = createHMAC(key_HMAC) #HMAC object

    KeysHA = key_AES + key_HMAC #concatenated keys
    
    cipherText_Keys_Bytes = encryptRSA(publicKeyFile, KeysHA) #encrypt AES and HMAC keys with rsa encryption
    publicKeyFile.close()

    cipherText_Keys_String = b64encode(cipherText_Keys_Bytes).decode('utf-8')

    cipherText = b64encode(cipherText_Message_Bytes).decode('utf-8') #convert cipher text from bytes to string

    h.update(cipherText_Message_Bytes)

    HMAC_tag = h.hexdigest()

    JSON_output = json.dumps({'AES_ciphertext' : cipherText, 'RSA_ciphertext' : cipherText_Keys_String, 'HMAC_Tag' : HMAC_tag }) 
    
    # outfile = open("Testing.encrypt", "w")
    # outfile.write(JSON_output)
    # outfile.close()



    #return JSON_output #return json object containing encrypted keys, ciphertexts, and HMAC tag
    return cipherText, cipherText_Keys_String, HMAC_tag

def decryptMessage(privateKeyAddress, AES, RSA_ciphertext, Tag):
    print('Checking integrity of message . . . . . . . .')

    try:
        # JSON = JSON_output.read()#read file

        # JSON_output = json.loads(JSON)

        # AES_ciphertext = b64decode(JSON_output['AES_ciphertext'])
        AES_ciphertext = b64decode(AES)

        #RSA_ciphertext = b64decode(JSON_output['RSA_ciphertext']) #encrypted keys
        RSA_keys = b64decode(RSA_ciphertext)
        # HMAC_tag = JSON_output['HMAC_Tag']
        HMAC_tag = Tag
      
        privateKeyFile = open(privateKeyAddress, 'rb')
        privateKey = RSA.generate(2048) #generate rsa key object
        privateKey = RSA.import_key(privateKeyFile.read()) #create rsa private key object
        privateKeyFile.close() #close key file

        keys_plaintext = decryptRSA(privateKey, RSA_keys)

        key_AES = keys_plaintext[0:32]
        key_HMAC = keys_plaintext[32:64]

        hm = createHMAC(key_HMAC)

        hm.update(AES_ciphertext)

        # if hm.verify(HMAC_tag.encode('utf-8')):
        #     print('mac tag is authentic')
        # else:
        #     print('message or key is wrong')
        
        try:
            hm.hexverify(HMAC_tag)
            print('the message is authentic')
            print('Decrypting message . . . . . . . . .')
            
        except ValueError:
            print('The message or key is wrong')
            return
        
        #separate iv from cipher text
        iv = AES_ciphertext[0:16]
        # print('iv: ', iv)
        AES_ciphertext = AES_ciphertext[16: 144]
        # print('AES_ciphertext: ', AES_ciphertext)

        plainText = decryptAES(key_AES,AES_ciphertext, iv) #decrypt AES
       
        # print("Plain text: ", plainText)


        #GUI IF YOU HAVE TIME
        # master = tk.Tk()
        # msg = tk.Message(master, text = plainText)
        # msg.config(bg='lightblue', font=('times',24,'italic'))
        # msg.pack()
        # tk.mainloop()


        # outfile = open("Testing.decrypt", "w")
        # outfile.write(plainText)
        # outfile.close()
        return plainText
    except ValueError:
        print('Decryption Failed. . . . . . .')


    return 


# #MAIN FUNCTION
# publicKeyAddress = input('Please enter the address of your public key: ')
# message = input('Please enter message to encrypt:')

# #JSON_output = encryptMessage(publicKeyAddress, message)
# encryptMessage(publicKeyAddress, message)
# JSON_output = open('Testing.encrypt', 'r')

# privateKeyAddress = input('Please enter the address of your private key: ')

# decryptMessage(privateKeyAddress, JSON_output)









