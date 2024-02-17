# pip install pycryptodome
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from datetime import datetime

from socket import *
import cv2
import os

from communicationCommands import *
from server import recieve_message_segment

class Client:
    def __init__(self) -> None:
        self.publicKey, self.privateKey, self.userId = self.license_setup()

    def license_setup(self) -> None:
        key = RSA.generate(2048)
        private_Key = key.export_key()
        public_key = key.publickey().export_key()

        username = input("username: ")
        password = SHA256.new(bytes(input("password: "), 'utf-8')).digest()
        private = PKCS1_v1_5.new(RSA.import_key(private_Key))
        sig = private.sign(SHA256.new(username.encode() + password + public_key))

        request = REQUEST_SETUP % (username,password.hex(), public_key.hex(),sig.hex())
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.connect(('127.0.0.1', 65432))
            sock.send(request.encode())
            # GET FROM SERVER USER ID, LEASE TIME, SYNCHRONISATION LOCATION AND TIME (USE GPS TO CHANGE GIVE TIME FOR CURRENT LOCATION)
            data, message = recieve_message_segment(sock)
            if (setup_command := data.get(COMMAND_SYNCHRONISE, None)) != None and setup_command == REPLY:
                user_id = int(data.get(HEADER_USER_ID, None))
        return public_key, private_Key, user_id
    
    def take_photo(self, filepath: str, gps_allowed: bool, time_allowed: bool) -> None:

        if time_allowed:
            now = datetime.now()
            localTime = int(bin(now.year)[2:].zfill(12) + bin(now.month)[2:].zfill(4) + bin(now.day)[2:].zfill(5) + bin(now.hour)[2:].zfill(5) + bin(now.minute)[2:].zfill(6), 2).to_bytes(4, "big")
        else:
            localTime = int(0).to_bytes(4, "big")

        if gps_allowed:
            # GET REAL LOCATION (to minutes)
            negativeLongitude = 0
            longitude = 180*60
            negativeLatitude = 0
            latitude = 90*60
            location = int(bin(negativeLongitude)[2:].zfill(1) + bin(longitude)[2:].zfill(15) + bin(negativeLatitude)[2:].zfill(1) + bin(latitude)[2:].zfill(15), 2).to_bytes(4, "big")
        else:
            location = int(0).to_bytes(4, "big")

        id = int.to_bytes(self.userId, 4, "big")
        
        cam = cv2.VideoCapture(0)
        result, image = cam.read()
        if result:
            cv2.imshow("Preview", image) 
            result,buffer = cv2.imencode(".jpg", image)
            if result:
                photo = buffer.tobytes()
                message = photo + b''.join([id, location, localTime])
                signature = PKCS1_v1_5.new(RSA.import_key(self.privateKey)).sign(SHA256.new(message))
                message += signature
                try:
                    with open(filepath, 'wb') as file:
                        file.write(message)
                        print(f"Image data successfully written to photo.jpg")
                except IOError as e:
                    print(f"An error occurred while writing the image file: {e}")
            cv2.waitKey(0) 
            cv2.destroyWindow("Preview")
        return
    
    def retrieve_user_public_key(self, userId:int) -> bytes:
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.connect(('127.0.0.1', 65432))
            request = REQUEST_VALIDATE % (userId)
            sock.send(request.encode())
            data, message = recieve_message_segment(sock)
            if (setup_command := data.get(COMMAND_VALIDATE, None)) != None and setup_command == REPLY:
                publicKey = bytes.fromhex(data.get(HEADER_PUBLIC_KEY, None))
        return publicKey
    
    def validate_photo(self, filepath: str) -> bool:
        try:
            with open(filepath, 'rb') as file:
                file_bytes = file.read()
                signature = file_bytes[-256:]
                userId = int.from_bytes(file_bytes[-268:-264], "big")
                # GET PUBLIC KEY FROM SERVER FROM USER ID
                publicKey = self.retrieve_user_public_key(userId)
                public = PKCS1_v1_5.new(RSA.import_key(publicKey))
                if public.verify(SHA256.new(file_bytes[:-256]), signature):
                    return True
                else:
                    return False
        except FileNotFoundError:
            print(f"File not found")
            return False
        except IOError as e:
            print(f"An error occurred while reading the file: {e}")
            return False
        
    def get_photo_metadata(self, filepath: str) -> None:
        try:
            with open(filepath, 'rb') as file:
                file_bytes = file.read()
                time = bin(int.from_bytes(file_bytes[-260:-256], "big"))[2:].zfill(32)
                year = int(time[0:12],2)
                month = int(time[12:16],2)
                day = int(time[16:21],2)
                hour = int(time[21:26],2)
                minute = int(time[26:],2)

                location = bin(int.from_bytes(file_bytes[-264:-260], "big"))[2:].zfill(32)
                negativeLongitude = int(location[0],2)
                longitude = int(location[1:16],2)
                negativeLatitude = int(location[16],2)
                latitude = int(location[17:],2)

                userId = int.from_bytes(file_bytes[-268:-264], "big")
                print(f"user id: {userId}\ntime: {year}-{month}-{day}-{hour}-{minute}\nlocation: long-{longitude/60} lat-{latitude/60}")
        except FileNotFoundError:
            print(f"File not found")
        except IOError as e:
            print(f"An error occurred while reading the file: {e}")

if __name__ == "__main__":
    client = Client()
    client.take_photo("image.jpg", False, False)
    client.get_photo_metadata("image.jpg")
    print(client.validate_photo("image.jpg"))