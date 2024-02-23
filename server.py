from serverCommunication import *

from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from threading import Thread

from socket import *

import datetime

database_Username_Data = {}
database_Id_Username = {}

class SignInDatabase:
    def __init__(self, id: int, username: str, passwordH: bytes, publicKey: bytes, expiryDate: bytes) -> None:
        self.id = id
        self.username = username
        self.passwordH = passwordH
        self.publicKey = publicKey
        self.expiryDate = expiryDate

class Server:
    
    database_Username_Data = None
    database_Id_Username = None

    def __init__(self) -> None:
        self.database_Username_Data = {}
        self.database_Id_Username = {}
        self.run()

    def run(self) -> None:
        threads = []
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', 65432))
            sock.listen(1)
            print(sock.getsockname())
            while True:
                connectionSocket, addr = sock.accept()
                thread = Thread(target=self.client_thread, args=(connectionSocket,))
                thread.start()
                threads.append(thread)

    def client_thread(self, sock:socket, buffer: bytes = bytes()) -> None:
        data, buffer = ServerCommunication.recieve_message_segment(sock, buffer)
        id = data.get(HEADER_USER_ID, None)
        uname = data.get(HEADER_USERNAME, None)
        hashedP = data.get(HEADER_HASHED_PASSWORD, None)
        publicK = data.get(HEADER_PUBLIC_KEY, None)
        signature = data.get(HEADER_SIGNATURE, None)
        pictureDate = data.get(HEADER_EXPIRY_DATE, None)
        # print(data)
        if (setup_command := data.get(COMMAND_SETUP, None)) != None and setup_command == REQUEST:
            print(COMMAND_SETUP, uname)
            reply = self.setup_request(uname, hashedP, publicK, signature)
        elif (setup_command := data.get(COMMAND_RENEW, None)) != None and setup_command == REQUEST:
            print(COMMAND_RENEW, uname)
            reply = ServerCommunication.form_invalid_reply()
        elif (setup_command := data.get(COMMAND_VALIDATE, None)) != None and setup_command == REQUEST:
            print(COMMAND_VALIDATE, id, pictureDate)
            reply = self.validate_request(id, pictureDate)
        else:
            reply = ServerCommunication.form_invalid_reply()
        sock.send(reply.encode())
        sock.close()
        return
    
    def setup_request(self, uname: str = None, hashedP: str = None, publicK: str = None, signature: str = None) -> str:
        if not (uname and hashedP and publicK and signature):
            return ServerCommunication.form_invalid_reply()
        
        if (data:=self.database_Username_Data.get(bytes.fromhex(uname).decode(), None)) != None:
            if data.passwordH != hashedP:
                return ServerCommunication.form_invalid_reply()
            return ServerCommunication.form_setup_reply(int.to_bytes(data.id, 12, ENDIAN), data.expiryDate)
        
        username = bytes.fromhex(uname)
        passwordH = bytes.fromhex(hashedP)
        publicKey = bytes.fromhex(publicK)
        public = PKCS1_v1_5.new(RSA.import_key(publicKey))
        verify = public.verify(SHA256.new(username + passwordH + publicKey), bytes.fromhex(signature))
        if verify:
            decodedUname = username.decode()
            userId = len(database_Id_Username.keys())

            # GENERATE EXPIRAY DATE FRO GIVEN LICENSE
            expiryDate = "2025-01-01".encode()
            user_data = SignInDatabase(userId, decodedUname, passwordH, publicKey, expiryDate)
            database_Username_Data[decodedUname] = user_data
            database_Id_Username[userId] = decodedUname
            print("<VALID SETUP REQUEST>")
            return ServerCommunication.form_setup_reply(userId.to_bytes(12, ENDIAN), expiryDate)
        else:
            return ServerCommunication.form_invalid_reply()
        
    def validate_request(self, id: str = None, pictureDate: str = None):
        invalid = ServerCommunication.form_invalid_reply()
        if not (id and pictureDate):
            return invalid
        id = int(id, base=16)
        if (username := database_Id_Username.get(id, None)) != None and (user_data := database_Username_Data.get(username, None)) != None:
            try:
                photoDate = bytes.fromhex(pictureDate).decode().split("-")
                expiryDate = user_data.expiryDate.decode().split("-")
                if len(photoDate) == 3 and datetime.datetime(int(photoDate[0]), int(photoDate[1]), int(photoDate[2])) <= datetime.datetime(int(expiryDate[0]), int(expiryDate[1]), int(expiryDate[2])):
                    print("<VALID VALIDATE REQUEST>")
                    return ServerCommunication.form_validation_reply(user_data.username.encode(), user_data.publicKey)
            except:
                return invalid

        return invalid

if __name__ == "__main__":
    server = Server()