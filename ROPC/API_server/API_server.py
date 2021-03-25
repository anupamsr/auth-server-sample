import json

# import ssl

from auth import verify_access_token
from flask import Flask, request

app = Flask(__name__)


@app.before_request
def before_request():
    # Checks if the access token is present and valid.
    auth_header = request.headers.get("Authorization")
    if "Bearer" not in auth_header:
        return json.dumps({"error": "Access token does not exist."}), 400

    try:
        access_token = auth_header.split(" ")[1]
        verify_access_token(access_token)
    except Exception as e:
        return json.dumps({"error": str(e)}), 400


@app.route("/users", methods=["GET"])
def get_user():
    # Returns a list of users.
    users = [
        {"username": "Jane Doe", "email": "janedoe@example.com"},
        {"username": "John Doe", "email": "johndoe@example.com"},
    ]

    return json.dumps({"results": users})


if __name__ == "__main__":
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # context.load_cert_chain('domain.crt', 'domain.key')
    # app.run(port = 5000, debug = True, ssl_context = context)
    app.run(port=5002, debug=True)
