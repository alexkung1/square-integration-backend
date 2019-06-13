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

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/test.db"
db = SQLAlchemy(app)

### NGROK
base_url = "https://278417fc.ngrok.io/"


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
permissions = ["PAYMENTS_READ", "PAYMENTS_WRITE"]

#################################
#################################
#################################

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


@app.route("/login")
def login():
    return render_template("login.html", tokens=tokens)

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/authenticate_user", methods=["GET"])
def authenticate_user():
    

@app.route("/register")
def register():
    return render_template("register.html", url=base_url+"register_backend", home=base_url)

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


if __name__ == "__main__":
    app.run(debug=True)
