# IMPORTANT unless you want Lizzo hell
# App Client MUST NOT have a client secret enabled

import boto3
import getpass
import json
import uuid
import hmac
import hashlib
import base64
from datetime import datetime

# =========================
# Configuration
# =========================

CLIENT_ID = "3t83eunupeq021a66921bk45q5"
AWS_DEFAULT_REGION = "us-east-1"

# =========================
# User Input
# =========================

username = input("Username in Cognito User Pool: ")
password = getpass.getpass("Password: ")
region = input("AWS Region where the Cognito User Pool is (e.g. us-east-1): ")
client_id = input("App Client ID: ")
client_secret = getpass.getpass("App Client Secret (if applicable, otherwise leave blank): ")

# =========================
# Secret Hash Computation
# =========================

# courtesy of chatGPT transforming original shell command to Python
# original shell command == echo -n "<USER_NAME><CLIENT_ID>" | openssl dgst -sha256 -hmac "<CLIENT_SECRET>" -binary | base64

def generate_signature(user_name: str, client_id: str, client_secret: str) -> str:
    payload = (user_name + client_id).encode("utf-8")
    secret = client_secret.encode("utf-8")

    hmac_digest = hmac.new(
        secret,
        payload,
        hashlib.sha256,
    ).digest()

    return base64.b64encode(hmac_digest).decode("utf-8")


# =========================
# Cognito Client
# =========================

client = boto3.client("cognito-idp", region_name=region)

try:
    auth_parameters = {
        "USERNAME": username,
        "PASSWORD": password,
    }

    # Only include SECRET_HASH if your Cognito app client has a client secret.
    if client_secret:
        secret_hash = generate_signature(
            username,
            client_id,
            client_secret,
        )

        print(f"the computed secret hash: {secret_hash}")

        auth_parameters["SECRET_HASH"] = secret_hash

    response = client.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters=auth_parameters
    )

    # =========================
    # Handle MFA Challenge
    # =========================

    if response.get("ChallengeName") == "SOFTWARE_TOKEN_MFA":
        code = input("Enter MFA Code: ")

        challenge_responses = {
            "USERNAME": username,
            "SOFTWARE_TOKEN_MFA_CODE": code,
        }

        if client_secret:
            challenge_responses["SECRET_HASH"] = secret_hash

        response = client.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=response["Session"],
            ChallengeResponses=challenge_responses
        )

    # =========================
    # Extract Tokens
    # =========================

    auth = response["AuthenticationResult"]

    print("\n========== TOKENS ==========\n")

    print("Access Token:\n")
    print(auth["AccessToken"])

    print("\n============================\n")

    # =========================
    # DynamoDB Validation
    # =========================

    dynamodb = boto3.resource("dynamodb", region_name=region)
    table = dynamodb.Table("token-trackingv2")

    token_id = str(uuid.uuid4())
    issued_at = datetime.utcnow().isoformat()

    table.put_item(
        Item={
            "token_id": token_id,
            "username": username,
            "issued_at": issued_at,
            "used": False
        }
    )

    print("\n========== DYNAMODB RECORD CREATED ==========")
    print(f"Table: {table.name}")
    print(f"token_id: {token_id}")
    print(f"username: {username}")
    print(f"issued_at: {issued_at}")
    print("used: False")
    print("=============================================\n")

except Exception as e:
    print("\nAuthentication Failed\n")
    print(str(e))
