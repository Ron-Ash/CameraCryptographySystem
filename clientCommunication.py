from communication import *

class ClientCommunication(Communication):
    @staticmethod
    def form_setup_request(uname: str, hashP: bytes, publicK: bytes, sig: bytes) -> str:
        return f"{COMMAND_SETUP}:{REQUEST}\n{HEADER_USERNAME}:" + uname.encode().hex() + f"\n{HEADER_HASHED_PASSWORD}:" + hashP.hex() + f"\n{HEADER_PUBLIC_KEY}:" + publicK.hex() + f"\n{HEADER_SIGNATURE}:" + sig.hex() + TERMINATION_LINE
    
    @staticmethod
    def form_renew_request(uname: str, hashP: bytes, newPublicK: bytes, sig: bytes) -> str:
        return f"{COMMAND_RENEW}:{REQUEST}\n{HEADER_USERNAME}:" + uname.encode().hex() + f"\n{HEADER_HASHED_PASSWORD}:" + hashP.hex() + f"\n{HEADER_PUBLIC_KEY}:" + newPublicK.hex() + f"\n{HEADER_SIGNATURE}:" + sig.hex() + TERMINATION_LINE
    
    @staticmethod
    def form_validation_request(id: bytes, time: bytes) -> str:
        return f"{COMMAND_VALIDATE}:{REQUEST}\n{HEADER_USER_ID}:" + id.hex() + f"\n{HEADER_EXPIRY_DATE}:" + time.hex() + TERMINATION_LINE
