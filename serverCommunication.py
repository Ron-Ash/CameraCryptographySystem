from communication import *

class ServerCommunication(Communication):
    @staticmethod
    def form_setup_reply(id: bytes, expiryDate: bytes) -> str:
        return f"{COMMAND_SETUP}:{REPLY}\n{HEADER_USER_ID}:" + id.hex() + f"\n{HEADER_EXPIRY_DATE}:" + expiryDate.hex() + TERMINATION_LINE
    
    @staticmethod
    def form_renew_reply(id: bytes, expiryDate: bytes) -> str:
        return f"{COMMAND_RENEW}:{REPLY}\n{HEADER_USER_ID}:" + id.hex() + f"\n{HEADER_EXPIRY_DATE}:" + expiryDate.hex() + TERMINATION_LINE
    
    @staticmethod
    def form_validation_reply(uname: bytes, publicK: bytes) -> str:
        return f"{COMMAND_VALIDATE}:{REPLY}\n{HEADER_USERNAME}:" + uname.hex() + f"\n{HEADER_PUBLIC_KEY}:" + publicK.hex() + TERMINATION_LINE
    
    @staticmethod
    def form_invalid_reply() -> str:
        return f"{COMMAND_FAILURE}:{REPLY}" + TERMINATION_LINE