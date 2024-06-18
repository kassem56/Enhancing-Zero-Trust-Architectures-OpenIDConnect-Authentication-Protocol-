# Client Side

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class OpenIDConnect:
    def __init__(self, op_url, rp_url, username, password):
        self.op_url = op_url
        self.rp_url = rp_url
        self.username = username
        self.password = password
        self.access_token = None
        self.identity_token = None
        self.session_id = None
        self.nonce = None

    # Encrypt nonce
    def encrypt_nonce(self, nonce, key):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(nonce)
        return ciphertext, tag

    # Decrypt nonce
    def decrypt_nonce(self, ciphertext, tag, nonce, key):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            return plaintext
        except ValueError:
            print("Decryption failed!")
            return None

    def user_sign_in(self):
        print("Enhancement Step: The end user signs in and inputs their credentials (username and password).")
        # Step 2: User signs in and inputs credentials
        # Not implemented in this example
        pass

    def request_identity_token(self):
        print("Enhancement Step: A request is sent to the OpenID Provider (OP) by the relying party (RP).")
        # Step 3: Request sent to OpenID Provider (OP)
        response = requests.get(f"{self.op_url}/authenticate", params={"username": self.username, "password": self.password})
        if response.status_code == 200:
            # Step 4: OP validates user credentials, authenticates, and authorizes user
            data = response.json()
            self.identity_token = data.get("identity_token")
            self.session_id = data.get("identity_token").get("session_id")
            self.nonce = data.get("identity_token").get("nonce")
            print("Received identity token:", self.identity_token)
            print("Received session ID:", self.session_id)
            print("Received nonce:", self.nonce)

    def request_access_token(self):
        print("Enhancement Step: The OpenID Provider (OP) replies to the relying party (RP) with both an identity token and often an access token.")
        if self.identity_token:
            # Step 5: OP replies to the relying party (RP) with both an identity token and often an access token
            response = requests.post(f"{self.op_url}/token", json={"identity_token": self.identity_token})
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                print("Received access token:", self.access_token)
            else:
                print("Failed to obtain access token:", response.status_code)
        else:
            print("Identity token not available.")

    def access_resource(self):
        print("Enhancement Step: The user device receives a request from the relying party (RP) that includes the access token.")
        if self.access_token:
            # Step 6: User device receives a request from the relying party (RP) that includes the access token
            headers = {"Authorization": f"Bearer {self.access_token}"}
            try:
                # Encrypt nonce
                ciphertext, tag = self.encrypt_nonce(self.nonce.encode(), b'password for AES is Kassem')

                # Send encrypted nonce to server
                response = requests.get(f"{self.rp_url}/resource", params={"nonce": ciphertext.hex(), "tag": tag.hex()})
                if response.status_code == 200:
                    print("Enhancement Step: Claims regarding the end-user are returned by the UserInfo endpoint.")
                    user_info = response.json()
                    print("User Info:", user_info)
                else:
                    print("Failed to access resource:", response.status_code)
            except Exception as e:
                print("An error occurred:", e)
        else:
            print("Access token not available.")

# Example usage
op_url = "http://127.0.0.1:5000/openid"  # Assuming Flask application is running locally
rp_url = "http://127.0.0.1:5000/rp"
username = "user@example.com"
password = "password123"

openid_connect = OpenIDConnect(op_url, rp_url, username, password)
openid_connect.user_sign_in()
openid_connect.request_identity_token()
openid_connect.request_access_token()
openid_connect.access_resource()
