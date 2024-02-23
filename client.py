from clientCommunication import *

# pip install pycryptodome
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from cryptography.fernet import Fernet, InvalidToken

import os

from datetime import datetime

from socket import *

import cv2

import random

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
            return
        self.take_photo("Image", True, -87*56, 157*43)
        self.photo_validation("Image")

    def setup_license(self)-> tuple[int, str] | tuple[None, None]:
        try:
            privateEncrypt = PKCS1_v1_5.new(RSA.import_key(self.userKey.decrypt_user_privateKey()))
        except InvalidToken as e:
            print(f"<ERROR>\tIncorrect password given")
            return None, None
        except IOError as e:
            print(f"<ERROR>\tUnexpected error occured {e}")
            return None, None
        preSignatureHash = SHA256.new(self.userKey.username.encode() + self.userKey.hashPassword + self.userKey.publicKey)
        signature = privateEncrypt.sign(preSignatureHash)
        message = ClientCommunication.form_setup_request(self.userKey.username, self.userKey.hashPassword, self.userKey.publicKey, signature)

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

    def fake_images(self, photoD: bytes, id: bytes, gpsLocation: bytes, localTime: bytes, signature: bytes) -> None:
        with open("photoD" + IMAGE_TYPE, 'wb') as file:
            tmp = photoD
            val = random.randint(0, len(tmp)-1)
            tmp = tmp[:val] + bytes([0x20]) + tmp[val+1:]
            file.write(tmp + id + gpsLocation + localTime + signature)
        if not self.photo_validation("photoD"): # expect the validity check to fail causing False to be returned
            os.remove("photoD" + IMAGE_TYPE)

        with open("id" + IMAGE_TYPE, 'wb') as file:
            tmp = id
            val = random.randint(0, len(tmp)-1)
            tmp = tmp[:val] + bytes([0x20]) + tmp[val+1:]
            file.write(photoD + tmp + gpsLocation + localTime + signature)
        if not self.photo_validation("id"): # expect the COMMAND_FAILURE to be returned (id not found) causing False to be returned
            os.remove("id" + IMAGE_TYPE)

        with open("gpsLocation" + IMAGE_TYPE, 'wb') as file:
            tmp = gpsLocation
            val = random.randint(0, len(tmp)-1)
            tmp = tmp[:val] + bytes([0x20]) + tmp[val+1:]
            file.write(photoD + id + tmp + localTime + signature)
        if not self.photo_validation("gpsLocation"): # expect the validity check to fail causing False to be returned
            os.remove("gpsLocation" + IMAGE_TYPE)

        with open("localTime" + IMAGE_TYPE, 'wb') as file:
            tmp = localTime
            val = random.randint(0, len(tmp)-1)
            tmp = tmp[:val] + bytes([0x20]) + tmp[val+1:]
            file.write(photoD + id + gpsLocation + tmp + signature)
        if not self.photo_validation("localTime"): # expect the validity check to fail causing False to be returned
            os.remove("localTime" + IMAGE_TYPE)

        with open("signature" + IMAGE_TYPE, 'wb') as file:
            tmp = signature
            val = random.randint(0, len(tmp)-1)
            tmp = tmp[:val] + bytes([0x20]) + tmp[val+1:]
            file.write(photoD + id + gpsLocation + localTime + tmp)
        if not self.photo_validation("signature"): # expect the validity check to fail causing False to be returned
            os.remove("signature" + IMAGE_TYPE)

        
    def take_photo(self, filepath: str, letLocalTime: bool = False, latitude: int = 0, longitude: int = 0):
        # Header data is stored in big endian
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

                self.fake_images(photoD, id, gpsLocation, localTime, signature)

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
                data, buffer = ClientCommunication.recieve_message_segment(sock)
                if (setup_command := data.get(COMMAND_VALIDATE, None)) != None and setup_command == REPLY:
                    uname = data.get(HEADER_USERNAME, None)
                    publicK = bytes.fromhex(data.get(HEADER_PUBLIC_KEY, None)).decode()
                    
                    public = PKCS1_v1_5.new(RSA.import_key(publicK))
                    if public.verify(SHA256.new(fileBytes[:-256]), signature):
                        print(f"<VALID IMAGE>\tInformation about image:\n\tuser name = {bytes.fromhex(uname).decode()}, user id = {id}\n\ttime photo taken = year-month-day hour:minute = {localTime}\n\tcoordinates(minues) = [latitude, longitude] = [{latitude}, {longitude}]")
                        sock.close()
                        return True
                    else:
                        print(f"<INVALID IMAGE>\tValidity failed")
                elif (setup_command := data.get(COMMAND_FAILURE, None)) != None and setup_command == REPLY:
                    print(f"<INVALID IMAGE>\tData given to server caused a COMMAND_FAILURE message")
                else:
                    print(f"<ERROR>\tIncorrect message recieved")
        except FileNotFoundError:
            print(f"<ERROR>\tFile not found")
        except IOError as e:
            print(f"<ERROR>\tOccurred while reading the file: {e}")
        return False

if __name__ == "__main__":
    Camera()