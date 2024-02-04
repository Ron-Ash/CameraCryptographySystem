import communicationCommands as command
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from threading import Thread
from socket import *
import ssl

database = {}

class SignInDatabase:
    def __init__(self, id: int, username: str, passwordH: str, publicKey: str) -> None:
        self.id = id
        self.username = username
        self.passwordH = passwordH
        self.publicKey = publicKey

def recieve_message_segment(sock: socket, buffer = bytes()) -> tuple[dict, bytes]:
    message = None
    while True:
        tmp = buffer.find(command.TERMINATION_LINE.encode())
        if tmp != -1:
            message = buffer[:tmp]
            buffer = buffer[tmp+2:]
            break
        buffer += sock.recv(1024)
    data = command.decomposeMessage(message.decode())
    return data,buffer

def recieve_command(sock: socket, buffer = bytes()) -> bytes:
    data, buffer = recieve_message_segment(sock, buffer)
    print(data)
    # OPERATE ON MESSAGE
    if (setup_command := data.get(command.COMMAND_SETUP, None)) != None and setup_command == command.REQUEST:
        username = bytes(data.get(command.HEADER_USERNAME, None), "utf-8")
        passwordH = data.get(command.HEADER_HASHED_PASSWORD, None)
        publicKey = data.get(command.HEADER_PUBLIC_KEY, None)
        sig = data.get(command.HEADER_SIGNATURE, None)
        if username and passwordH and publicKey and sig:
            public = PKCS1_v1_5.new(RSA.import_key(bytes.fromhex(publicKey)))
            verify = public.verify(SHA256.new(username + bytes.fromhex(passwordH) + bytes.fromhex(publicKey)), bytes.fromhex(sig))
            if verify:
                # GENERATE IDS MORE EFFECTIVELY
                userId = len(database.keys())
                user_data = SignInDatabase(userId, username, passwordH, publicKey)
                database[userId] = user_data
                reply = command.REPLY_SYNCHRONISE % (userId, "None", "None", "None")
                sock.send(reply.encode())
                print("Valid SETUP request given and user setup ")
    if (setup_command := data.get(command.COMMAND_VALIDATE, None)) != None and setup_command == command.REQUEST:
        print("A")
        userId = int(data.get(command.HEADER_USER_ID, None))
        if (user_data := database.get(userId, None)) != None:
            reply = command.REPLY_VALIDATE % (user_data.username, user_data.publicKey)
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