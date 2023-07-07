import os
import json
import functools
import urllib3
import requests
import time
from flask import Flask, request
from keycloak import KeycloakOpenID

print = functools.partial(print, flush=True)  # Make print always flush after

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)  # Disable ssl warnings


allowed_client_id = os.environ.get("ALLOW_REQUESTS_KEYCLOAK_CLIENT_ID")
print(
    "[INFO] Only allowing requests from the {} keycloak client".format(
        allowed_client_id
    )
)
spi_endpoint = os.environ.get("SPI_ENDPOINT_URL")
print("[INFO] Output url set to ---> {}".format(spi_endpoint))

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
        print("[ERROR] Could not get Access token from keycloak: {}".format(err))


get_keycloak_token()
token_introspect = keycloak_openid.introspect(access_token)
if not token_introspect["active"]:
    print("[ERROR] Access token is not valid: {}".format(token_introspect))
print("[INFO] Own Access token is valid: {}".format(token_introspect))


print("\n<--- Zeek notice receiver --->\n")
app = Flask(__name__)


@app.before_request
def check_access_token_age():
    if time.time() > token_exp_ts:
        get_keycloak_token()


@app.route("/zeek-logs", methods=["POST"])
def zeek_logs():
    if "Authorization" not in request.headers.keys():
        print("[WARN] Request authorization header missing")
        return {"status": "error", "msg": "unauthorized"}, 401

    try:
        request_introspect = keycloak_openid.introspect(
            request.headers["Authorization"].split()[1]  # Parse access token
        )
    except Exception as err:
        print("[ERROR] Could not get token introspection from keycloak: {}".format(err))
        return {"status": "error", "msg": "unauthorized"}, 401

    if not request_introspect["active"]:
        print("[WARN]: Request access token is not valid")
        return {"status": "error", "msg": "unauthorized"}, 401

    if request_introspect["clientId"] != allowed_client_id:
        print(
            "[WARN]: Request access token client is not valid: {}".format(
                request_introspect
            )
        )
        return {"status": "error", "msg": "unauthorized"}, 403

    try:
        zeek_notice_event = request.get_json()
        if len(zeek_notice_event) == 0:
            print("[ERROR]: Empty JSON object")
            return {"status": "error", "msg": "invalid data"}, 400
    except Exception as err:
        print("[ERROR]: Could not parse JSON data: {}".format(err))
        return {"status": "error", "msg": "invalid json"}, 400

    print("[INFO] New Zeek notice event: {}".format(zeek_notice_event))

    try:
        requests.post(spi_endpoint, json=zeek_notice_event, verify=False)
    except Exception as err:
        print("[ERROR]: Could not post event data to SPI: {}".format(err))
        return {"status": "error", "msg": "fail to redirect data to SPI"}, 400

    return {"status": "success"}, 200
