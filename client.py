# pip install pycryptodome
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from cryptography.fernet import Fernet

import os

class AsymmetricKey:
    username = None
    password = None
    privateKeyEncrypted = None
    publicKey = None
    hashPassword = None
    def __init__(self, username: str  = input("Enter username: ")) -> None:
        self.username = username
        privateKeyFileName = username+"_PrivateKey_Encrypted.txt"
        publicKeyFileName = username + "_PublicKey.txt"
        if os.path.isfile(privateKeyFileName):
            self.password = input("Enter password: ").encode()
            with open(privateKeyFileName, 'rb') as file:
                self.privateKeyEncrypted = file.read()
            with open(publicKeyFileName, 'rb') as file:
                self.publicKey = file.read()
        else:
            self.password, self.privateKeyEncrypted, self.publicKey = self.create_asymmetric_key(privateKeyFileName, publicKeyFileName)
        
        self.hashPassword = SHA256.new(self.password).digest()

    def create_asymmetric_key(self, privateKeyFileName: str, publicKeyFileName: str) -> tuple[bytes, bytes, bytes]:
        key = RSA.generate(2048)
        privateKey = key.export_key()
        publicKey = key.publickey().export_key()
        password = Fernet.generate_key()
        fernet = Fernet(password)
        print(f"Generated Password: {password.decode()}")
        privateKeyEncrypted = fernet.encrypt(privateKey)

        with open(privateKeyFileName, 'wb') as file:
            file.write(privateKeyEncrypted)
        with open(publicKeyFileName, 'wb') as file:
            file.write(publicKey)

        return password, privateKeyEncrypted, publicKey
    
    def decrypt_user_privateKey(self) -> bytes:
        return Fernet(self.password).decrypt(self.privateKeyEncrypted)

from datetime import datetime

from socket import *

import cv2

# from server import recieve_message_segment

from communicationCommands import *

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

class Camera:
    userKey = None
    expiryDate = None
    id = None
    def __init__(self, userKey: AsymmetricKey = AsymmetricKey()) -> None:
        self.userKey = userKey
        # check if id and expiryDate are already existant
        self.id, self.expiryDate = self.setup_license()
        if self.id == None or self.expiryDate == None:
            print("<ERROR>\tcould not setup license")
        self.take_photo("Image", True, -87*56, 157*43)
        self.photo_validation("Image")

    def setup_license(self)-> tuple[int, str] | tuple[None, None]:
        privateEncrypt = PKCS1_v1_5.new(RSA.import_key(self.userKey.decrypt_user_privateKey()))
        preSignatureHash = SHA256.new(self.userKey.username.encode() + self.userKey.hashPassword + self.userKey.publicKey)
        signature = privateEncrypt.sign(preSignatureHash)
        message = ClientCommunication.form_setup_request(self.userKey.username, self.userKey.hashPassword, self.userKey.publicKey, signature)
        # print(message)

        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.connect(('127.0.0.1', 65432))
            sock.send(message.encode())
            # GET FROM SERVER USER ID, and LEASE TIME
            data, buffer = ClientCommunication.recieve_message_segment(sock)
            if (setup_command := data.get(COMMAND_SETUP, None)) != None and setup_command == REPLY:
                userId = int(data.get(HEADER_USER_ID, None))
                expiryDate = bytes.fromhex(data.get(HEADER_EXPIRY_DATE, None)).decode()
                return userId, expiryDate
        return None, None

    # def renew_license(self):
    #     pass

    def take_photo(self, filepath: str, letLocalTime: bool = False, latitude: int = 0, longitude: int = 0):
        # Header data is stored in big endian
        ENDIAN = "big"
        IMAGE_TYPE = ".jpg"
        if not letLocalTime:
            localTime = int.to_bytes(0, 16, ENDIAN, signed=True)
        else:
            localTime = str(datetime.now())[:-10].encode() #16bytes long string in the format: year-month-day hour:minute
        gpsLocation = int.to_bytes(latitude, 2, ENDIAN, signed=True) + int.to_bytes(longitude, 2, ENDIAN, signed=True) # latitude and longitude are measured in minutes (60minutes = 1degree) - latitude in [-90,90]*60, longitude in [-180,180]*60, data segments are in [-32767, 32767]
        id = int.to_bytes(self.id, 12, ENDIAN)
        # print(self.id, latitude, longitude, localTime.decode())

        cam = cv2.VideoCapture(0)
        result, image = cam.read()
        if result:
            cv2.imshow("Preview", image)
            result,buffer = cv2.imencode(IMAGE_TYPE, image)
            if result:
                photoD = buffer.tobytes()
                message = photoD + id + gpsLocation + localTime
                privateEncrypt = PKCS1_v1_5.new(RSA.import_key(self.userKey.decrypt_user_privateKey()))
                preSignatureHash = SHA256.new(message)
                signature = privateEncrypt.sign(preSignatureHash)
                print(len(signature))
                message = message + signature
                try:
                    with open(filepath + IMAGE_TYPE, 'wb') as file:
                        file.write(message)
                        print(f"<SUCCESS>\tImage saved into {IMAGE_TYPE}")
                except IOError as e:
                    print(f"<ERROR>\tOccurred while writing the image file: {e}")
                cv2.waitKey(0)
                return
            print(f"<ERROR>\tData could not be converted into {IMAGE_TYPE}")
        print(f"<ERROR>\tData could not be read from camera")


    def photo_validation(self, filepath: str) -> bool:
        ENDIAN = "big"
        IMAGE_TYPE = ".jpg"
        try:
            with open(filepath + IMAGE_TYPE, 'rb') as file:
                fileBytes = file.read()
            signature = fileBytes[-256:]
            id = int.from_bytes(fileBytes[-288:-276], ENDIAN)
            latitude = int.from_bytes(fileBytes[-276:-274], ENDIAN, signed=True)
            longitude = int.from_bytes(fileBytes[-274:-272], ENDIAN, signed=True)
            localTime = fileBytes[-272:-256].decode()
            # print(id, latitude, longitude, localTime)
            message = ClientCommunication.form_validation_request(int.to_bytes(id, 12, ENDIAN), localTime.split(" ")[0].encode())

            with socket(AF_INET, SOCK_STREAM) as sock:
                sock.connect(('127.0.0.1', 65432))
                sock.send(message.encode())
                # GET FROM SERVER USER ID, and LEASE TIME
                data, buffer = ClientCommunication.recieve_message_segment(sock)
                if (setup_command := data.get(COMMAND_VALIDATE, None)) != None and setup_command == REPLY:
                    uname = data.get(HEADER_USERNAME, None)
                    publicK = bytes.fromhex(data.get(HEADER_PUBLIC_KEY, None)).decode()
                    
                    public = PKCS1_v1_5.new(RSA.import_key(publicK))
                    if public.verify(SHA256.new(fileBytes[:-256]), signature):
                        print(f"<VALID IMAGE>\t{uname}:{id} {localTime} Lat:{latitude} Lon:{longitude}")
                        return True
                    else:
                        print(f"<INVALID IMAGE>")
                else:
                    print(f"<ERROR>\tIncorrect message recieved")
        except FileNotFoundError:
            print(f"<ERROR>\tFile not found")
        except IOError as e:
            print(f"<ERROR>\tOccurred while reading the file: {e}")
        return False

Camera()

# class Client:
#     def __init__(self) -> None:
#         self.publicKey, self.privateKey, self.userId = self.license_setup()

#     def license_setup(self) -> None:
#         key = RSA.generate(2048)
#         private_Key = key.export_key()
#         public_key = key.publickey().export_key()

#         username = input("username: ")
#         password = SHA256.new(bytes(input("password: "), 'utf-8')).digest()
#         private = PKCS1_v1_5.new(RSA.import_key(private_Key))
#         sig = private.sign(SHA256.new(username.encode() + password + public_key))

#         request = REQUEST_SETUP % (username,password.hex(), public_key.hex(),sig.hex())
#         with socket(AF_INET, SOCK_STREAM) as sock:
#             sock.connect(('127.0.0.1', 65432))
#             sock.send(request.encode())
#             # GET FROM SERVER USER ID, LEASE TIME, SYNCHRONISATION LOCATION AND TIME (USE GPS TO CHANGE GIVE TIME FOR CURRENT LOCATION)
#             data, message = recieve_message_segment(sock)
#             if (setup_command := data.get(COMMAND_SYNCHRONISE, None)) != None and setup_command == REPLY:
#                 user_id = int(data.get(HEADER_USER_ID, None))
#         return public_key, private_Key, user_id
    
#     def take_photo(self, filepath: str, gps_allowed: bool, time_allowed: bool) -> None:

#         if time_allowed:
#             now = datetime.now()
#             localTime = int(bin(now.year)[2:].zfill(12) + bin(now.month)[2:].zfill(4) + bin(now.day)[2:].zfill(5) + bin(now.hour)[2:].zfill(5) + bin(now.minute)[2:].zfill(6), 2).to_bytes(4, "big")
#         else:
#             localTime = int(0).to_bytes(4, "big")

#         if gps_allowed:
#             # GET REAL LOCATION (to minutes)
#             negativeLongitude = 0
#             longitude = 180*60
#             negativeLatitude = 0
#             latitude = 90*60
#             location = int(bin(negativeLongitude)[2:].zfill(1) + bin(longitude)[2:].zfill(15) + bin(negativeLatitude)[2:].zfill(1) + bin(latitude)[2:].zfill(15), 2).to_bytes(4, "big")
#         else:
#             location = int(0).to_bytes(4, "big")

#         id = int.to_bytes(self.userId, 4, "big")
        
#         cam = cv2.VideoCapture(0)
#         result, image = cam.read()
#         if result:
#             cv2.imshow("Preview", image) 
#             result,buffer = cv2.imencode(".jpg", image)
#             if result:
#                 photo = buffer.tobytes()
#                 message = photo + b''.join([id, location, localTime])
#                 signature = PKCS1_v1_5.new(RSA.import_key(self.privateKey)).sign(SHA256.new(message))
#                 message += signature
#                 try:
#                     with open(filepath, 'wb') as file:
#                         file.write(message)
#                         print(f"Image data successfully written to photo.jpg")
#                 except IOError as e:
#                     print(f"An error occurred while writing the image file: {e}")
#             cv2.waitKey(0) 
#             cv2.destroyWindow("Preview")
#         return
    
#     def retrieve_user_public_key(self, userId:int) -> bytes:
#         with socket(AF_INET, SOCK_STREAM) as sock:
#             sock.connect(('127.0.0.1', 65432))
#             request = REQUEST_VALIDATE % (userId)
#             sock.send(request.encode())
#             data, message = recieve_message_segment(sock)
#             if (setup_command := data.get(COMMAND_VALIDATE, None)) != None and setup_command == REPLY:
#                 publicKey = bytes.fromhex(data.get(HEADER_PUBLIC_KEY, None))
#         return publicKey
    
#     def validate_photo(self, filepath: str) -> bool:
#         try:
#             with open(filepath, 'rb') as file:
#                 file_bytes = file.read()
#                 signature = file_bytes[-256:]
#                 userId = int.from_bytes(file_bytes[-268:-264], "big")
#                 # GET PUBLIC KEY FROM SERVER FROM USER ID
#                 publicKey = self.retrieve_user_public_key(userId)
#                 public = PKCS1_v1_5.new(RSA.import_key(publicKey))
#                 if public.verify(SHA256.new(file_bytes[:-256]), signature):
#                     return True
#                 else:
#                     return False
#         except FileNotFoundError:
#             print(f"File not found")
#             return False
#         except IOError as e:
#             print(f"An error occurred while reading the file: {e}")
#             return False
        
#     def get_photo_metadata(self, filepath: str) -> None:
#         try:
#             with open(filepath, 'rb') as file:
#                 file_bytes = file.read()
#                 time = bin(int.from_bytes(file_bytes[-260:-256], "big"))[2:].zfill(32)
#                 year = int(time[0:12],2)
#                 month = int(time[12:16],2)
#                 day = int(time[16:21],2)
#                 hour = int(time[21:26],2)
#                 minute = int(time[26:],2)

#                 location = bin(int.from_bytes(file_bytes[-264:-260], "big"))[2:].zfill(32)
#                 negativeLongitude = int(location[0],2)
#                 longitude = int(location[1:16],2)
#                 negativeLatitude = int(location[16],2)
#                 latitude = int(location[17:],2)

#                 userId = int.from_bytes(file_bytes[-268:-264], "big")
#                 print(f"user id: {userId}\ntime: {year}-{month}-{day}-{hour}-{minute}\nlocation: long-{longitude/60} lat-{latitude/60}")
#         except FileNotFoundError:
#             print(f"File not found")
#         except IOError as e:
#             print(f"An error occurred while reading the file: {e}")

# if __name__ == "__main__":
#     # client = Client()
#     # client.take_photo("image.jpg", False, False)
#     # client.get_photo_metadata("image.jpg")
#     # print(client.validate_photo("image.jpg"))
#     key = AsymmetricKey("a", "b")