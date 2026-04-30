from flask import Flask, request
import bcrypt
import jwt
import datetime

app = Flask(__name__)

SECRET_KEY = "secret123"

users = []
blacklisted_tokens = []


def log_event(message):
    with open("security.log", "a") as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")


@app.route("/")
def home():
    return {"message": "SecureShield API is running"}


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    users.append({
        "username": username,
        "password": hashed,
        "role": role
    })

    return {"message": "User registered successfully"}


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    for user in users:
        if user["username"] == username:
            if bcrypt.checkpw(password.encode("utf-8"), user["password"]):

                token = jwt.encode({
                    "username": username,
                    "role": user["role"],
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }, SECRET_KEY, algorithm="HS256")

                return {"token": token}

    log_event(f"Failed login attempt for user: {username}")
    return {"message": "Invalid credentials"}, 401


@app.route("/protected", methods=["GET"])
def protected():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        log_event("Access attempt without token")
        return {"message": "Token is missing"}, 403

    token = auth_header.split(" ")[1] if " " in auth_header else auth_header

    if token in blacklisted_tokens:
        log_event("Access with blacklisted token")
        return {"message": "Token has been logged out"}, 401

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return {"message": f"Welcome {data['username']}!"}
    except:
        log_event("Invalid token used")
        return {"message": "Invalid token"}, 401


@app.route("/admin", methods=["GET"])
def admin():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        log_event("Admin access without token")
        return {"message": "Token is missing"}, 403

    token = auth_header.split(" ")[1] if " " in auth_header else auth_header

    if token in blacklisted_tokens:
        log_event("Admin access with blacklisted token")
        return {"message": "Token has been logged out"}, 401

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        if data["role"] != "admin":
            log_event(f"Unauthorized admin access attempt by {data['username']}")
            return {"message": "Access denied: Admins only"}, 403

        return {"message": f"Welcome admin {data['username']}!"}

    except:
        log_event("Invalid token used for admin access")
        return {"message": "Invalid token"}, 401


@app.route("/logout", methods=["POST"])
def logout():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        log_event("Logout attempt without token")
        return {"message": "Token is missing"}, 403

    token = auth_header.split(" ")[1] if " " in auth_header else auth_header

    blacklisted_tokens.append(token)
    log_event("User logged out and token blacklisted")

    return {"message": "User logged out successfully"}


if __name__ == "__main__":
    app.run(debug=True)