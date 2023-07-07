import os
import time
import urllib3
import requests
import functools
from flask import Flask, request
from keycloak import KeycloakOpenID

print = functools.partial(print, flush=True)  # Make print always flush after

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)  # Disable ssl warnings

redirect_url = os.environ.get("REDIRECT_URL")

keycloak_openid = KeycloakOpenID(
    server_url=os.environ.get("KEYCLOAK_SERVER_AUTH_URL"),
    verify=False,  # Don't verify SSL certificate
    realm_name=os.environ.get("KEYCLOAK_REALM_NAME"),
    client_id=os.environ.get("KEYCLOAK_CLIENT_ID"),
    client_secret_key=os.environ.get("KEYCLOAK_CLIENT_SECRET"),
)


def get_keycloak_token():
    try:
        global access_token, token_exp_ts
        token = keycloak_openid.token(grant_type="client_credentials")
        access_token = token["access_token"]
        token_exp_ts = (
            time.time() + token["expires_in"] * 0.9
        )  # Make some token lifetime headroom
    except Exception as err:
        print("[ERROR] Could not get access token from keycloak: {}".format(err))


get_keycloak_token()
token_introspect = keycloak_openid.introspect(access_token)
if not token_introspect["active"]:
    print("[ERROR] Access token is not valid: {}".format(token_introspect))
print("[INFO] Own Access token is valid: {}".format(token_introspect))

app = Flask(__name__)


@app.before_request
def check_access_token_age():
    if time.time() > token_exp_ts:
        get_keycloak_token()


@app.route("/zeek-logs", methods=["POST"])
def zeek_logs():
    try:
        body = request.get_json()
        zeek_notice_event = body["zeek"]["notice"]
    except Exception as err:
        print("[ERROR] Could not parse zeek notice event data: {}".format(err))
        return {"status": "error"}, 400

    try:
        post_request = requests.post(
            redirect_url,
            json=zeek_notice_event,
            headers={"Authorization": "Bearer {}".format(access_token)},
            verify=False,
        )
        if post_request.status_code != 200:
            print(
                "[WARN] Destination did not properly receive the event data: {}".format(
                    post_request.json()
                )
            )
    except Exception as err:
        print("[ERROR] Could not post event data: {}".format(err))

    return {"status": "success"}, 200
