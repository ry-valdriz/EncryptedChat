import requests
import json
from encrypt_decrypt import encryptMessage, decryptMessage

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
        if(choice == 1):
            Register()
        elif(choice == 2):
            Login()
        else:
            print("---------------")
            print("Exiting DuoDolo")
            print("---------------")
            break

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
            chat(jwt)
            return
    elif(r.status_code == 500): #server error
        print("Server Error")
        return
    elif(r.status_code == 404):
        print("No user with that email") #no matching accounts
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
    


