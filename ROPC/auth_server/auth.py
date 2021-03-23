import jwt
import time

ISSUER = "sample-auth-server"
LIFE_SPAN = 1800

with open("private.pem", "rb") as f:
    private_key = f.read()


def authenticate_user_credentials(username, password):
    from cryptography import exceptions

    try:
        import json

        with open("../../db.json", "r") as f:
            data = json.load(f)
            db_user = data["li"]["username"]
            db_pass = data["li"]["password"]
            import mysql.connector

            with mysql.connector.connect(
                host="localhost",
                user=db_user,
                password=db_pass,
                database="li",
                raw=True,
            ) as cnx:
                cursor = cnx.cursor()
                cursor.execute(
                    """SELECT salt, hashed_key FROM li_auth WHERE username=%s""",
                    (username,),
                )
                row = cursor.fetchone()
                salt = bytes(row[0])
                hashed_key = bytes(row[1])
                from cryptography.hazmat.primitives.kdf import scrypt

                kdf = scrypt.Scrypt(salt=salt, length=128, n=2 ** 14, r=8, p=1)
                import base64

                kdf.verify(
                    bytes(password, "utf-8"), base64.urlsafe_b64decode(hashed_key)
                )
    except exceptions.InvalidKey:
        return False
    return True


def authenticate_client(client_id, client_secret):
    return True


def generate_access_token():
    payload = {
        "iss": ISSUER,
        "exp": time.time() + LIFE_SPAN,
    }

    access_token = jwt.encode(payload, private_key, algorithm="RS256")
    return access_token
