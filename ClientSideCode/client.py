import requests
import json
from encrypt_decrypt import encryptMessage, decryptMessage

def Login():
    #https://www.pythonforbeginners.com/requests/using-requests-in-python
    url = 'http://localhost:3000/api/auth/login'
    print("Logging in" + "\n" + "-------------")
    email = input("Email: ")
    password = input("Password: ")
    payload = {'email': email, 'password':password}
    r = requests.post(url, payload)#POST request to server

    #check response codes
    if(r.status_code == 200): #everything worked
        json_response = r.json()
        if(json_response['auth'] == False):
            print("Incorrect Password/Email")
            return
        else: #
            jwt = json_response['token']
            #print('jwt', jwt)
            chat(jwt)
            return
    elif(r.status_code == 500): #server error
        print("Server Error")
        return
    elif(r.status_code == 404):
        print("No user with that email" + "\n") #no matching accounts
        return
    else: #hopefully doesn't happen
        print("Something went wrong with " + url + " route")
        return

def Register():
    url = 'http://localhost:3000/api/auth/register'
    print("Registering")
    print("------------")
    name = input("Name: ")
    email = input("Email: ")
    password = input("Password: ")
    payload = {'name' : name, 'email' : email, 'password' : password}
    r = requests.post(url, payload)

    if(r.status_code == 200): #everything went well
        json_response = r.json()
        jwt = json_response['token']
        #print('jwt',jwt)
        chat(jwt)
        return
    elif(r.status_code == 500): #problem registering the user
        print("There was a problem registering the user" + "\n")
        return
    elif(r.status_code == 404): #user with same email found
        print("User found with same email" + "\n")
        return
    else:
        print("Something went wrong with " + url + " route")
        return
    
def chat(jwt):
    send_url = 'http://localhost:3000/api/mess/send'
    receive_url = 'http://localhost:3000/api/mess/receive'
    
    while(1):
        print("\n" + "--------------------" + "\n"+  "CHAT" + "\n" + "--------------------")
        print("1. Send")
        print("2. Receive")
        print("3. Exit")
        choice = input("Please select a number: ")

        if(choice == '1'): #send
            recipient = input("Please enter email of recipient: ")
            message = input("message: ")
            publicKeyAddress = input("Please enter address of public key: ")
            
            AES, RSA, Tag = encryptMessage(publicKeyAddress, message)
            payload = {'recipient' : recipient, 'AES' : AES, 'RSA' : RSA, 'Tag' : Tag}
            headers = {'x-access-token' : jwt}

            r = requests.post(send_url, data = payload, headers = headers)
            #check response codes
            if(r.status_code == 500):
                print("Error sending the message. . .")
            elif(r.status_code == 200):
                print("Message sent . . . ")
            else:
                print("Something went wrong. . . ")

        elif(choice == '2'): #receive
            privateKeyAddress = input("Please enter the address of your private key: ")
            print('')
            headers = {'x-access-token' : jwt}
            r = requests.get(receive_url, headers = headers)
            #print('status code: ',r.status_code)
            json_response = r.json()
            #print('json response', json_response)
            r.raise_for_status()
            #iterate through messages
            #print('before the loop')
            for x in json_response:
                #print('in the loop')
                sender = x['sender']
                recipient = x['recipient']
                AES = x['AES']
                RSA = x['RSA']
                Tag = x['Tag']
                #print('cipher text', ciphertext)
                plainText = decryptMessage(privateKeyAddress, AES, RSA, Tag)
                print("-----------------------------------------")
                print("Sender: ", sender)
                print("Recipient: ", recipient)
                print("Message: " , plainText)
                print("-----------------------------------------")
                print("")
        else:
            print("Exiting. . . ." + "\n")
            return 

    return


def main():
    print("----------------------")
    print("DuoDolo encrypted chat")
    print("----------------------" + "\n")

    while(True): #reiterate the app until the user decides to exit
        print("1. Register")
        print("2. Login")
        print("3. Quit")
        choice = input("Select a number: ")
        print("")
        if(choice == '1'):
            Register()
        elif(choice == '2'):
            Login()
        else:#exit
            print("---------------")
            print("Exiting DuoDolo")
            print("---------------")
            break

main()
