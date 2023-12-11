# pip install pycryptodome
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from datetime import datetime
from communicationCommands import *
import cv2
import os

class Client:
    def __init__(self) -> None:
        self.publicKey, self.privateKey, self.userId = self.license_setup()
        self.take_photo("image.jpg", True, True)
        print(self.validate_photo("image.jpg"))
        self.get_photo_metadata("image.jpg")
        pass

    def license_setup(self) -> None:
        key = RSA.generate(2048)
        private_Key = key.export_key()
        public_key = key.publickey().export_key()

        username = bytes(input("username: "), 'utf-8')
        password = SHA256.new(bytes(input("password: "), 'utf-8')).digest()
        pu = public_key

        private = PKCS1_v1_5.new(RSA.import_key(private_Key))
        sig = private.sign(SHA256.new(username + password + pu))

        request = REQUEST_SETUP % (username,password, pu,sig)
        # SEND SERVER PUBLIC KEY, USERNAME, PASSWORD HASH
        # GET FROM SERVER USER ID
        user_id = 2
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
                # print(id, location, localTime)
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
    
    def validate_photo(self, filepath: str) -> bool:
        try:
            with open(filepath, 'rb') as file:
                file_bytes = file.read()
                signature = file_bytes[-256:]
                # print(file_bytes[-268:-256])
                userId = file_bytes[-268:-264]
                # GET PUBLIC KEY FROM SERVER FROM USER ID
                public = PKCS1_v1_5.new(RSA.import_key(self.publicKey))
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


# def setup():
#     key = RSA.generate(2048)
#     private_Key = key.export_key()
#     public_key = key.publickey().export_key()

#     username = bytes(input("username: "), 'utf-8')
#     password = SHA256.new(bytes(input("password: "), 'utf-8')).digest()
#     pu = bytes(public_key)

#     private = PKCS1_v1_5.new(RSA.import_key(private_Key))
#     sig = private.sign(SHA256.new(username + password + pu))

#     request = REQUEST_SETUP % (username,password, pu,sig)
#     # SEND REQUEST TO SERVER
#     # license_time = 
#     # user_id = 
#     # SAVE CONFIDENTIAL INFROMATION IN SECURED FILE (user password used to encrypt file)
#     # START TIMER INTERUPT TO RENEW LICENSE
#     # return user_id, license_time, private_key
#     return bytes(1), "22/11/2023", bytes(private_Key), pu

# def take_image(cam, user_id, private_Key, gps_allowed, time_allowed):
#     result, image = cam.read()
#     if result:
#         cv2.imshow("Preview", image) 
#         result,buffer = cv2.imencode(".jpg", image)
#         if result:
#             photo = buffer.tobytes()
#             message = photo + user_id + (b'0:0' if gps_allowed else b'1:1') + (b'12:0' if time_allowed else b'0:0')
#             signature = PKCS1_v1_5.new(RSA.import_key(private_Key)).sign(SHA256.new(message))
#             print(signature)
#             message += signature
#             try:
#                 with open("photo.jpg", 'wb') as file:
#                     file.write(message)
#                     print(f"Image data successfully written to photo.jpg")
#             except IOError as e:
#                 print(f"An error occurred while writing the image file: {e}")
#         cv2.waitKey(0) 
#         cv2.destroyWindow("Preview")

# def verify_image(filepath, user_id, public_key):
#     # COMMUNICATE WITH SERVER TO RECIEVE PUBLIC KEY FROM USER ID
#     try:
#         with open(filepath, 'rb') as file:
#             file_bytes = file.read()
#             signature = file_bytes[-256:]
#             print(signature)
#             public = PKCS1_v1_5.new(RSA.import_key(public_key))
#             if public.verify(SHA256.new(file_bytes[:-256]), signature):
#                 print(f"Signature match in photo {filepath}")
#             else:
#                 print(f"Signature mismatch in photo {filepath}")
#     except FileNotFoundError:
#         print(f"The file '{filepath}' was not found.")
#     except IOError as e:
#         print(f"An error occurred while reading the file: {e}")

# # if __name__ == "__main__":
# #     cam_port = 0
# #     cam = cv2.VideoCapture(cam_port)
# #     if os.path.exists("credentials.pem"):
# #         with open("credentials.pem", 'r') as file:
# #             file_contents = file.read().split("\n")
# #             user_id = file_contents[0]
# #             license_time = file_contents[1]
# #             private_Key = file_contents[2]
# #     else:
# #         user_id, license_time, private_key, public_key = setup()
    
# #     mode = input("Operation Mode {A - No GPS and No Time data, B - Only GPS data, C - Only Time data, D - GPS and Time data}:\n").upper()
# #     if mode == "A":
# #         take_image(cam, user_id, private_key, False, False)
# #     elif mode == "B":
# #         take_image(cam, user_id, private_key, True, False)
# #     elif mode == "C":
# #         take_image(cam, user_id, private_key, False, True)
# #     elif mode == "D":
# #         take_image(cam, user_id, private_key, True, True)

# #     verify_image('photo.jpg', 1, public_key)

# # print(type(bin(6)[2:].zfill(8)))
# # from datetime import datetime
# # now = datetime.now()

# # localTime = int(bin(now.year)[2:].zfill(12) + bin(now.month)[2:].zfill(4) + bin(now.day)[2:].zfill(5) + bin(now.hour)[2:].zfill(5) + bin(now.minute)[2:].zfill(6), 2).to_bytes(4, "big")

# # negativeLongitude = 0
# # longitude = 180
# # negativeLatitude = 0
# # latitude = 90
# # location = int(bin(negativeLongitude)[2:].zfill(1) + bin(longitude)[2:].zfill(15) + bin(negativeLatitude)[2:].zfill(1) + bin(latitude)[2:].zfill(15), 2).to_bytes(4, "big")

# # userId = 12
# # id = int.to_bytes(userId, 4, "big")

# # print(b''.join([id, location, localTime]))
# # print(id)
# # print(location)
# # print(localTime)

client =Client()