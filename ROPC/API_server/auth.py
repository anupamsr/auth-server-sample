import jwt

ISSUER = "sample-auth-server"

with open("public.pem", "rb") as f:
    public_key = f.read()


def verify_access_token(access_token):
    try:
        jwt.decode(
            access_token.encode(), public_key, issuer=ISSUER, algorithms=["RS256"]
        )
    except jwt.exceptions.InvalidIssuerError:
        raise Exception("Access token has invalid issuer.")
    except jwt.exceptions.ExpiredSignatureError:
        raise Exception("Access token has expired signature.")
    except jwt.exceptions.InvalidTokenError:
        raise Exception("Access token is invalid.")
    except jwt.exceptions.InvalidSignatureError:
        raise Exception("Access token has invalid signature.")
