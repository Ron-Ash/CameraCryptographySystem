# Camera Cryptography System
With the increasing issue of AI as pertains to untruthful images and video (deep-fakes), I can see that in 1-5 years generated images/videos would be indistinguishable (https://openai.com/sora) from real footage and as a result many issues could arise, from court admission of fake video as evidence to incriminate innocent people to liable being unchallenged and the spread of fake news.

While researching this, I saw that current solutions to this problem are AI powered deep-fake analysis programs that look at the video/image and try to discern its authenticity. However, I see this as a possible cat and mouse game that will continue until deepfakes are indistinguishable. Also, at some point the AI powered analysers will intake fake footage as real bringing the game to an end. Therefore I think a different solution would have to be used.

The solution I propose rely on the concept of Public Key Infrastructure where a trusted server distributes, stores, manages, and validates user certificates; providing public keys of users to others so they could validate images/videos of users.

## Design
![image](https://github.com/Ron-Ash/CameraCryptographySystem/assets/37012505/0fcc7885-6854-4d19-af67-f3b89972e3b0)<br>
The image above describes the signature creation process (ideally done in hardware). 
  1. The camera sensor provides the stream of data of a given image/video as well as a randomly initialised incrementing counters called Starting/Ending "Frame ID" (photo has Starting Frame ID = Ending Frame ID, video has Ending Frame ID = Starting Frame ID + No. of Frames in video).
  2. The User ID is provided by the server, identifying the user without connecting them directly (name, etc.)
  3. GPS coordinates and local time taken from internal hardware to ensure that footage taken could not be used to misrepresent other events.
These data segments are concatonated into a message, hashed using an agreed on (server-wide) cryptographic hashing algorithm (ideally hardware-based) and then encrypted into a signature using an agreed on (server-wide) digital signature generation algorithm (ideally hardware-based) with the user's private key.

This signature is then stored with the image in a .uath file (POC stores signature in last 256 bits + 32bits per infromation segments of .jpg file) which can then be validated by other parties possessing the correct public key.

![image](https://github.com/Ron-Ash/CameraCryptographySystem/assets/37012505/4a6e0bf6-6a7b-40a3-8ec6-216cb371759b)
![image](https://github.com/Ron-Ash/CameraCryptographySystem/assets/37012505/53083f57-f377-4e52-ba9f-311ca354de74)
These images above demonstrate the main functionalities the client and server provide to accomplish the solution:
- License Setup: in these functionalities, the client will generate their asymmetric key to be used in the PKI system as well as generate (user inputted) a username and password to identify and authenticate the user to the server. A connection would then be established between the client and server to exchange their information and setup the client dataset (public key, hashed password, username, id, lease time). Ideally the client will then also set a callback loop to when the lease expires to renew the licence.
- Photo Generation: in this functionality applies the signature creation protocol with that of the normal photo taking protocol.
- License Renewal:  in these functionalities initiate after the lease time expired, where the server would stop providing the public key to validate photos taken after the lease time and the client would have to establish a connection with the server and apply to a new licensce (recieving a new lease time).
- Photo Validation:  in these functionalities, a client reading .auth (or POC's .jpg file) retrieves the user id and time from the image/video. Then it establishes a connection with the server and provides this information to it to recieve the public key of the image/video's author, allowing the client to test the image/video's validity. 

## Development Environment:
1. Clone the repository:  ``` > git clone https://github.com/Ron-Ash/CameraCryptographySystem.git ```
2. run ``` server.py ```
3. run ``` client.py ```

This will have the client program create an asymmetric key, take a photo from the computer's camera and follow the signature creation pathway. Then it will concatonate the signature to the message (image, user id, ...) and save it all as a image.jpg. Then it will validate the created image, printing True or False if the image is valid.

Note: this program only acomplishes a very basic form of the design without the licensce renewals or the GPS/time data (though does provide empty data segments for it). Also does not implement the Starting/Ending Frame ID.
