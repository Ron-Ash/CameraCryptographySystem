HEADER_COMMAND = "%s:%s\n"
COMMAND_SETUP = "SETUP"
COMMAND_VALIDATE = "VALIDATE"
COMMAND_RENEW = "RENEW"
COMMAND_SYNCHRONISE = "SYNCHRONISE"
COMMAND_FAILURE = "FAILURE"
REQUEST = "REQUEST"
REPLY = "REPLY"
HEADER_USERNAME = "Username"
HEADER_USER_ID = "Id"
HEADER_HASHED_PASSWORD = "HashedPassword"
HEADER_PUBLIC_KEY = "PublicKey"
HEADER_SIGNATURE = "Signature"
HEADER_GPS_LOCATION = "GPS location"
HEADER_LOCAL_TIME = "Local Time"
HEADER_EXPIRY_DATE = "Expiry date"
TERMINATION_LINE = "\r\n"

REQUEST_SETUP = (HEADER_COMMAND % (COMMAND_SETUP,REQUEST)) + HEADER_USERNAME+":%s\n" + HEADER_HASHED_PASSWORD+":%s\n" + HEADER_PUBLIC_KEY+":%s\n" + HEADER_SIGNATURE+":%s" + TERMINATION_LINE
REQUEST_RENEW = (HEADER_COMMAND % (COMMAND_RENEW,REQUEST)) + HEADER_USERNAME+":%s\n" + HEADER_HASHED_PASSWORD+":%s\n" + HEADER_PUBLIC_KEY+":%s\n" + HEADER_SIGNATURE+":%s" + TERMINATION_LINE
REPLY_SYNCHRONISE = (HEADER_COMMAND % (COMMAND_SYNCHRONISE,REPLY)) + HEADER_USER_ID+":%s\n" + HEADER_GPS_LOCATION+":%s\n" + HEADER_LOCAL_TIME+":%s\n" + HEADER_EXPIRY_DATE+":%s" + TERMINATION_LINE
REQUEST_VALIDATE = (HEADER_COMMAND % (COMMAND_VALIDATE,REQUEST)) + HEADER_USER_ID+":%s" + TERMINATION_LINE
REPLY_VALIDATE = (HEADER_COMMAND % (COMMAND_VALIDATE,REPLY)) + HEADER_USERNAME+":%s\n" + HEADER_PUBLIC_KEY+":%s" + TERMINATION_LINE
REPLY_ERROR = (HEADER_COMMAND % (COMMAND_FAILURE,REPLY)) + TERMINATION_LINE

#Forbidden character \n, \r,
# input without terminating line
def decomposeMessage(message: str)->dict:
    tmp = message.split("\n")
    dictionary = dict()
    for header in tmp:
        head, value = header.split(":", 1)
        dictionary[head] = value
    return dictionary

username = "username"
password = "asdgasodasmyssidh-3u2yefowp"
pu = "adhbfeqy8y8n0wuefuhsixamn"
sig = "asda"
gps = "123:324:444"
time = "11/11/2023 00:12"
expiry = "11/12/2024 00:12"

# print(REQUEST_SETUP % (username,password, pu,sig))