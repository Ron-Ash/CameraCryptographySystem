from communicationCommands import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from threading import Thread
from socket import *
import ssl

class ServerCommunication(Communication):
    @staticmethod
    def form_setup_reply(id: bytes, expiryDate: bytes) -> str:
        return f"{COMMAND_SETUP}:{REPLY}\n{HEADER_USER_ID}:" + id.hex() + f"\n{HEADER_EXPIRY_DATE}:" + expiryDate.hex() + TERMINATION_LINE
    
    @staticmethod
    def form_renew_reply(id: bytes, expiryDate: bytes) -> str:
        return f"{COMMAND_RENEW}:{REPLY}\n{HEADER_USER_ID}:" + id.hex() + f"\n{HEADER_EXPIRY_DATE}:" + expiryDate.hex() + TERMINATION_LINE
    
    @staticmethod
    def form_validation_reply(uname: str, publicK: bytes) -> str:
        return f"{COMMAND_VALIDATE}:{REPLY}\n{HEADER_USERNAME}:" + uname.hex() + f"\n{HEADER_PUBLIC_KEY}:" + publicK.hex() + TERMINATION_LINE
    
    @staticmethod
    def form_invalid_reply() -> str:
        return f"{COMMAND_FAILURE}:{REPLY}" + TERMINATION_LINE

database = {}

class SignInDatabase:
    def __init__(self, id: int, username: str, passwordH: str, publicKey: str) -> None:
        self.id = id
        self.username = username
        self.passwordH = passwordH
        self.publicKey = publicKey

def recieve_command(sock: socket, buffer = bytes()) -> bytes:
    data, buffer = ServerCommunication.recieve_message_segment(sock, buffer)
    print(data)
    # OPERATE ON MESSAGE
    if (setup_command := data.get(COMMAND_SETUP, None)) != None and setup_command == REQUEST:
        username = data.get(HEADER_USERNAME, None)
        passwordH = data.get(HEADER_HASHED_PASSWORD, None)
        publicKey = data.get(HEADER_PUBLIC_KEY, None)
        sig = data.get(HEADER_SIGNATURE, None)
        print("reached A")
        if username and passwordH and publicKey and sig:
            username = bytes.fromhex(username)
            passwordH = bytes.fromhex(passwordH)
            publicKey = bytes.fromhex(publicKey)
            public = PKCS1_v1_5.new(RSA.import_key(publicKey))
            verify = public.verify(SHA256.new(username + passwordH + publicKey), bytes.fromhex(sig))
            if verify:
                print("reached B")
                # GENERATE IDS MORE EFFECTIVELY
                userId = len(database.keys())
                user_data = SignInDatabase(userId, username, passwordH, publicKey)
                database[userId] = user_data
                # reply = REPLY_SYNCHRONISE % (userId, "None", "None", "None")
                reply = ServerCommunication.form_setup_reply(userId.to_bytes(12, "big"), b"2025-03-31")
                sock.send(reply.encode())
                print("Valid SETUP request given and user setup ")
    if (setup_command := data.get(COMMAND_VALIDATE, None)) != None and setup_command == REQUEST:
        print("A")
        userId = int(data.get(HEADER_USER_ID, None))
        if (user_data := database.get(userId, None)) != None:
            # reply = REPLY_VALIDATE % (user_data.username, user_data.publicKey)
            reply = ServerCommunication.form_validation_reply(user_data.username, user_data.publicKey)
            sock.send(reply.encode())
        else:
            reply = ServerCommunication.form_invalid_reply()
            sock.send(reply.encode())

    return buffer

if __name__ == "__main__":
    threads = []
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 65432))
        sock.listen(1)
        print(sock.getsockname())
        while True:
            connectionSocket, addr = sock.accept()
            thread = Thread(target=recieve_command, args=(connectionSocket,))
            thread.start()
            threads.append(thread)