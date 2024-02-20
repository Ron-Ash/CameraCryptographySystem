# Camera Cryptography System
With the increasing issue of AI as pertains to images and video (deep-fakes), I can see that in 1-5 years generated images/videos would be indistinguishable (https://openai.com/sora) from real footage and as a result many issues could arise, from court admission of fake video as evidence to incriminating innocent people to liable being unchallenged and the spread of fake news.

While researching this, I saw that current solutions to this problem are AI powered deep-fake analysis programs that look at the video/image and try to discern its authenticity. However, I see this as a possible cat and mouse game that will continue until deepfakes are indistinguishable. Also, at some point, the AI powered analysers will intake fake footage as real bringing the game to an end. Therefore I think a different approach is required.

The solution I propose here relies on the concept of Public Key Infrastructure where a trusted server distributes, stores, manages, and validates camera manufacturer's certificates; providing public keys of cameras to users so they could validate images/videos taken with specific cameras.

## Design
![image](https://github.com/Ron-Ash/CameraCryptographySystem/assets/37012505/0fcc7885-6854-4d19-af67-f3b89972e3b0)<br>
The image above describes the process of signing an image/video as they are captured (ideally done in hardware). 
  1. The camera's sensor provides the stream of data of a given image/video as well as Starting/Ending Frame ID to keep track of the number of frames in a video (in a photo, Starting Frame ID = Ending Frame ID) 
  3. The user (camera) ID is provided by the server, identifying the camera without connecting them directly to a user (name, etc.)
  4. GPS coordinates and local time taken from internal hardware to ensure that footage taken could not be used out of context (time and location).
These data segments are concatenated into a message, hashed using an agreed on (server-wide) cryptographic hashing algorithm (ideally hardware-based) and then encrypted into a signature using an agreed on (server-wide) digital signature generation algorithm (ideally hardware-based) with the camera's private key.

This signature is then stored with the image in a .auth file (POC stores signature in last 256 bits + 32bits per information segments of .jpg file) which can then be validated by other parties possessing the correct public key.

![image](https://github.com/Ron-Ash/CameraCryptographySystem/assets/37012505/4a6e0bf6-6a7b-40a3-8ec6-216cb371759b)
![image](https://github.com/Ron-Ash/CameraCryptographySystem/assets/37012505/53083f57-f377-4e52-ba9f-311ca354de74)
The images above demonstrate the main functionalities the client (camera) and server provide to accomplish the solution:
- License Setup: the client will generate their asymmetric key to be used in the PKI system as well as generate (user input) a username and password to identify and authenticate the user to the server. A connection would then be established between the client and server to exchange their information and setup the client dataset (public key, hashed password, username, id, lease time). Ideally the client will then also set a callback loop to when the lease expires to renew the licence.
- Photo Generation: this functionality applies the signature creation protocol with that of the normal photo taking protocol.
- License Renewal:  After the lease time of the client's certificate expires, the server would not provide its public key until the client initiates a connection with it to renew the license
- Photo Validation:  a client reading .auth (or POC's .jpg file) retrieves the user id and time from the image/video. Then it establishes a connection with the server and provides this information to it to receive the public key of the image/video's author, allowing the client to test the image/video's validity. 

## Development Environment:
1. Clone the repository:  ``` > git clone https://github.com/Ron-Ash/CameraCryptographySystem.git ```
2. run ``` server.py ```
3. run ``` client.py ```
4. enter a username (unique), a password will be generated used to encrypt the stored Private Key (2 .txt files will be save containing the encrypted private key and the plaintext public key) which will be used in signing the photo.
    - note that subsequent running of the program with the same username (and .txt file names), thh program will skip the key creation process.
5. once a window pops up with the captured image, close it by either pressing spacebar while clicked on in or the "X" button, the image will then be stored under the name "Image.jpg"

This will have the client program create an asymmetric key, take a photo from the computer's camera and follow the signature creation pathway. Then it will concatenate the signature to the message (image, user id, ...) and save it all as a "Image.jpg". Afterwhich, the client program will attempt to validate whether "Image.jpg" has been manipulated or not, following the 3rd communication timeline seen above and printign at last that it is indeed a valid image.
  - note that Client() has a method fake_images() which when run with a valid set of photo data, user id, gpsLocation, localTime, and signature (all bytes) demonstrates that the validation function indeed detects manipulation within every part of the image.

Note: this program only accomplishes a very basic form of the design without the license renewals or the GPS/time data (though it does provide empty data segments for it). Also does not implement the Starting/Ending Frame ID.