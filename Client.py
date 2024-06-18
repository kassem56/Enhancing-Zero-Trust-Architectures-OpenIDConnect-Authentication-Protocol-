
# Client side : 


import requests

class OpenIDConnect:
    def __init__(self, op_url, rp_url, username, password):
        self.op_url = op_url
        self.rp_url = rp_url
        self.username = username
        self.password = password
        self.access_token = None
        self.identity_token = None
        self.session_id = None

    def user_sign_in(self):
        # Step 2: User signs in and inputs credentials
        # Not implemented in this example
        pass

    def request_identity_token(self):
        # Step 3: Request sent to OpenID Provider (OP)
        response = requests.get(f"{self.op_url}/authenticate", params={"username": self.username, "password": self.password})
        if response.status_code == 200:
            # Step 4: OP validates user credentials, authenticates, and authorizes user
            data = response.json()
            self.identity_token = data.get("identity_token")
            self.session_id = data.get("session_id")
            print("Received identity token:", self.identity_token)
            print("Received session ID:", self.session_id)

    def request_access_token(self):
        if self.identity_token:
            # Step 5: OP replies to the relying party (RP) with both an identity token and often an access token
            response = requests.post(f"{self.op_url}/token", data={"identity_token": self.identity_token})
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                print("Received access token:", self.access_token)
            else:
                print("Failed to obtain access token:", response.status_code)
        else:
            print("Identity token not available.")

    def access_resource(self):
        if self.access_token:
            # Step 6: User device receives a request from the relying party (RP) that includes the access token
            headers = {"Authorization": f"Bearer {self.access_token}"}
            try:
                response = requests.get(f"{self.rp_url}/resource", headers=headers)
                print("Request URL:", response.request.url)
                print("Request Headers:", response.request.headers)
                print("Response Status Code:", response.status_code)
                if response.status_code == 200:
                    # Step 7: Claims regarding the end-user are returned by the UserInfo endpoint
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



