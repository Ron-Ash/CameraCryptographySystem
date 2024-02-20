from socket import *

# HEADER_COMMAND = "%s:%s\n"
COMMAND_SETUP = "SETUP"
COMMAND_VALIDATE = "VALIDATE"
COMMAND_RENEW = "RENEW"
# COMMAND_SYNCHRONISE = "SYNCHRONISE"
COMMAND_FAILURE = "FAILURE"
REQUEST = "REQUEST"
REPLY = "REPLY"
HEADER_USERNAME = "Username"
HEADER_USER_ID = "Id"
HEADER_HASHED_PASSWORD = "HashedPassword"
HEADER_PUBLIC_KEY = "PublicKey"
HEADER_SIGNATURE = "Signature"
HEADER_GPS_LOCATION = "GPSLocation"
HEADER_LOCAL_TIME = "LocalTime"
HEADER_EXPIRY_DATE = "ExpiryDate"
TERMINATION_LINE = "\r\n"

# REQUEST_SETUP = (HEADER_COMMAND % (COMMAND_SETUP,REQUEST)) + HEADER_USERNAME+":%s\n" + HEADER_HASHED_PASSWORD+":%s\n" + HEADER_PUBLIC_KEY+":%s\n" + HEADER_SIGNATURE+":%s" + TERMINATION_LINE
# REQUEST_RENEW = (HEADER_COMMAND % (COMMAND_RENEW,REQUEST)) + HEADER_USERNAME+":%s\n" + HEADER_HASHED_PASSWORD+":%s\n" + HEADER_PUBLIC_KEY+":%s\n" + HEADER_SIGNATURE+":%s" + TERMINATION_LINE
# REPLY_SYNCHRONISE = (HEADER_COMMAND % (COMMAND_SYNCHRONISE,REPLY)) + HEADER_USER_ID+":%s\n" + HEADER_GPS_LOCATION+":%s\n" + HEADER_LOCAL_TIME+":%s\n" + HEADER_EXPIRY_DATE+":%s" + TERMINATION_LINE
# REQUEST_VALIDATE = (HEADER_COMMAND % (COMMAND_VALIDATE,REQUEST)) + HEADER_USER_ID+":%s" + TERMINATION_LINE
# REPLY_VALIDATE = (HEADER_COMMAND % (COMMAND_VALIDATE,REPLY)) + HEADER_USERNAME+":%s\n" + HEADER_PUBLIC_KEY+":%s" + TERMINATION_LINE
# REPLY_ERROR = (HEADER_COMMAND % (COMMAND_FAILURE,REPLY)) + TERMINATION_LINE

# #Forbidden character \n, \r,
# # input without terminating line
# def decomposeMessage(message: str)->dict:
#     tmp = message.split("\n")
#     dictionary = dict()
#     for header in tmp:
#         head, value = header.split(":", 1)
#         dictionary[head] = value
#     return dictionary


class Communication:
    @staticmethod
    def decomposeMessage(message: str) -> dict:
        tmp = message.split("\n")
        dictionary = dict()
        for header in tmp:
            head, value = header.split(":", 1)
            dictionary[head] = value
        return dictionary
    
    @staticmethod
    def recieve_message_segment(sock: socket, buffer: bytes = bytes()) -> tuple[dict, bytes]:
        message = None
        while True:
            print("-", end="")
            tmp = buffer.find(TERMINATION_LINE.encode())
            if tmp != -1:
                message = buffer[:tmp]
                buffer = buffer[tmp+2:]
                break
            buffer += sock.recv(1024)
        data = Communication.decomposeMessage(message.decode())
        return data,buffer

# username = "username"
# password = "asdgasodasmyssidh-3u2yefowp"
# pu = "adhbfeqy8y8n0wuefuhsixamn"
# sig = "asda"
# gps = "123:324:444"
# time = "11/11/2023 00:12"
# expiry = "11/12/2024 00:12"

# print(ClientCommunication.form_setup_request(username, password.encode(), pu.encode(), sig.encode()))
# print(ClientCommunication.form_renew_request(username, password.encode(), pu.encode(), sig.encode()))
# print(ClientCommunication.form_validation_request(b"12", expiry.encode()))

# print(ServerCommunication.form_setup_reply(b"12", expiry.encode()))
# print(ServerCommunication.form_renew_reply(b"12", expiry.encode()))
# print(ServerCommunication.form_validation_reply(username, pu.encode()))