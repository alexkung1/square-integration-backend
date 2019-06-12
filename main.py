from __future__ import print_function
from flask import Flask, request, g, jsonify, current_app, render_template
import requests
import squareconnect
from squareconnect.rest import ApiException
from squareconnect.apis.locations_api import LocationsApi
from squareconnect.apis.o_auth_api import OAuthApi
from squareconnect.models.obtain_token_request import ObtainTokenRequest
import json
import urllib

app = Flask(__name__)

location_id = "VKA3ZBDKC21TQ"
access_token = "EAAAECrvvArmS9YlaFw9q9UrDBvGTRokwReytSbjjjKVEIF5GaEI3417iLSQtDBq"
application_id = "sq0idp-e56RPKqT1rxul1sUO_9LHw"
application_secret = "sq0csp-34x7M-zMyS7UDNmNexHC26AgUzp6Povz3TQOmoizIGg"

oauth_api = OAuthApi()
_SQ_DOMAIN = "connect.squareup.com"


_SQ_AUTHZ_URL = "/oauth2/authorize"
tokens = {}
permissions = ["PAYMENTS_READ", "PAYMENTS_WRITE"]


def getObtainTokenRequest():
    r = requests.get("https://api.github.com/user", auth=("user", "pass"))


@app.route("/", methods=["GET", "POST"])
def home():
    # print("-------------------------")
    perms = " ".join(permissions)
    link = (
        "https://"
        + _SQ_DOMAIN
        + _SQ_AUTHZ_URL
        + "?client_id="
        + application_id
        + "&scope="
        + perms
    )
    link2 = urllib.parse.urlparse(link).geturl()

    # return "<a href='{}'>HELLO FRIENDS </a>".format(link)
    return render_template("main.html", url=link2, permissions=permissions)


@app.route("/request_token", methods=["POST"])
def request_token():
    data = json.loads(request.data)
    print(data)
    return "Hello, Salvador"


@app.route("/s_location", methods=["GET", "POST"])
def location():
    # create an instance of the Location API class
    api_instance = LocationsApi()
    # setup authorization
    api_instance.api_client.configuration.access_token = access_token

    try:
        # ListLocations
        api_response = api_instance.list_locations()
        print(api_response.locations)
    except ApiException as e:
        print("Exception when calling LocationApi->list_locations: %s\n" % e)
    return "Hello, Salvador"


@app.route("/callback", methods=["GET", "POST"])
def callback():

    # Extract the returned authorization code from the URL
    print("-----------------------------------------------------------")

    print(request.args.get("code"))
    print("-----------------------------------------------------------")
    authorization_code = request.args.get("code")
    if authorization_code:

        # Provide the code in a request to the Obtain Token endpoint
        oauth_request_body = ObtainTokenRequest()
        oauth_request_body.client_id = application_id
        oauth_request_body.client_secret = application_secret
        oauth_request_body.code = authorization_code
        oauth_request_body.grant_type = "authorization_code"

        response = oauth_api.obtain_token(oauth_request_body)

        if response.access_token:

            # Here, instead of printing the access token, your application server should store it securely
            # and use it in subsequent requests to the Connect API on behalf of the merchant.
            print("Access token: " + response.access_token)
            tokens["access_token"] = response.access_token
            return "Authorization succeeded!"

        # The response from the Obtain Token endpoint did not include an access token. Something went wrong.
        else:
            return "Code exchange failed!"

    # The request to the Redirect URL did not include an authorization code. Something went wrong.
    else:
        return "Authorization failed!"


if __name__ == "__main__":
    app.run(debug=True)
