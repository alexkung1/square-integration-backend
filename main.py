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
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from enum import Enum

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/test.db"
db = SQLAlchemy(app)

### NGROK
base_url = "https://278417fc.ngrok.io/"

#####################################
#######   MISC CONSTSANTS  ##########
#####################################


class Permission(Enum):
    PAYMENTS_READ = "PAYMENTS_READ"
    PAYMENTS_WRITE = "PAYMENTS_WRITE"
    INVENTORY_READ = "INVENTORY_READ"
    INVENTORY_WRITE = "INVENTORY_WRITE"
    TIMECARDS_READ = "TIMECARDS_READ"


AVAILABLE_WEBHOOKS = {
    "PAYMENT_UPDATED": {
        "Type": "A charge was made or refunded through Square Point of Sale or the Transaction API.",
        "Permission": Permission.PAYMENTS_READ.value,
    },
    "INVENTORY_UPDATED": {
        "Type": "The inventory quantity for a catalog item was updated.",
        "Permission": Permission.INVENTORY_READ.value,
    },
    "TIMECARD_UPDATED": {
        "Type": "A timecard was created in the Square dashboard or an employee clocked in using Square Point of Sale.",
        "Permission": Permission.TIMECARDS_READ.value,
    },
}


#####################################
#####################################
#####################################


#################################
#######   SQUARE AUTH  ##########
#################################

location_id = "VKA3ZBDKC21TQ"
access_token = "EAAAECrvvArmS9YlaFw9q9UrDBvGTRokwReytSbjjjKVEIF5GaEI3417iLSQtDBq"
application_id = "sq0idp-e56RPKqT1rxul1sUO_9LHw"
application_secret = "sq0csp-34x7M-zMyS7UDNmNexHC26AgUzp6Povz3TQOmoizIGg"

oauth_api = OAuthApi()
_SQ_DOMAIN = "connect.squareup.com"


_SQ_AUTHZ_URL = "/oauth2/authorize"
tokens = {}
permissions = [perm.value for perm in Permission]


SUPPORTED_APIS = [
    ("list_employees", "v1/me/employees"),
    ("list_payments", "v1/{}/payments".format(location_id)),
    ("list_items", "v1/{}/items".format(location_id)),
]

#################################
#################################
#################################

##################
### MOCK AUTH ####
##################
USER_TOKEN = "EAAAEG_Bhmh-L9VEkxlWHecl1h-tnQ2i8URrm_AP-Au4vEITiv9tiPYd2MLjfnaK"


def getUserToken():
    return USER_TOKEN


def setUserToken(token):
    USER_TOKEN = token


@app.route("/set_token")
def set_token():
    return render_template(
        "set_token.html", url=base_url + "set_token2", curr_token=USER_TOKEN
    )


@app.route("/set_token2", methods=["PATCH"])
def set_token2():
    token = json.loads(request.data).get("token")
    USER_TOKEN = token
    return "OK"


##################
##################
##################


######################################
#######   LOGIN MANAGEMENT  ##########
######################################

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    results = User.query.filter_by(id=user_id)
    if results.all():
        return results.first()
    else:
        return None


######################################
######################################
######################################


############################
#######   MODELS  ##########
############################


class Token(db.Model):
    __tablename__ = "Token"

    id = db.Column(db.Integer, primary_key=True)
    auth_token = db.Column(db.String)

    def __repr__(self):
        return "<Token(auth_token='%s')>" % (self.auth_token,)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_authenticated = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    is_anonymous = db.Column(db.Boolean, default=False)

    def get_id(self):
        return str(self.id).encode("utf-8").decode("utf-8")

    def __repr__(self):
        return "<User %r>" % self.username


############################
############################
############################


def getObtainTokenRequest():
    r = requests.get("https://api.github.com/user", auth=("user", "pass"))


#################################
########## ENDPOINTS ############
#################################


@app.route("/")
def home():
    return render_template("main.html")


@app.route("/auth", methods=["GET", "POST"])
def auth():
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

    return render_template("auth.html", url=link2, permissions=permissions)


@app.route("/login")
def login():
    return render_template("login.html", tokens=tokens)


@app.route("/register")
def register():
    return render_template(
        "register.html", url=base_url + "register_backend", home=base_url
    )


@app.route("/register_backend")
def register_backend():
    username = request.data.get("username")
    email = request.data.get("email")
    try:
        user = User(username=username, email=email)
        db.session.add(user)
        db.session.commit()
        return "Registration successful!"
    except:
        return "Registration failed"


@app.route("/request_token", methods=["POST"])
def request_token():
    data = json.loads(request.data)
    print(data)
    return "Hello, Salvador"


@app.route("/show_tokens")
def show_tokens():
    tokens = Token.query.all()
    return render_template("tokens.html", tokens=tokens)


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


@app.route("/settings")
def settings():
    # CHECK FOR A TOKEN OR SOMETHING
    return render_template("settings.html", webhooks=AVAILABLE_WEBHOOKS)


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
            token_str = response.access_token
            # print("Access token: " + token_str)
            # tokens["access_token"] = token_str
            token = Token(auth_token=token_str)
            db.session.add(token)
            db.session.commit()

            # return "Authorization succeeded!"
            return render_template("auth_success.html")

        # The response from the Obtain Token endpoint did not include an access token. Something went wrong.
        else:
            return "Code exchange failed!"

    # The request to the Redirect URL did not include an authorization code. Something went wrong.
    else:
        return "Authorization failed!"


@app.route("/api")
def api():
    return render_template(
        "api.html",
        user_token=getUserToken(),
        apis=SUPPORTED_APIS,
        base_url="https://" + _SQ_DOMAIN + "/",
    )


##################
# MOCK ENDPOINTS #
##################


@app.route("/mock_webhooks", methods=["PUT"])
def mock_webhooks():
    # CHECK FOR A TOKEN OR SOMETHING
    webhooks = json.loads(request.data).get("webhooks")
    print("RECEIVED THE FOLLOWING WEBHOOK REQUESTS:")
    for webhook in webhooks:
        print(webhook)

    return "SUCCESS"


if __name__ == "__main__":
    app.run(debug=True)
