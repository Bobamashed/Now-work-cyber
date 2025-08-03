from flask import Flask, render_template, request, redirect, session, flash, url_for
import json
from werkzeug.security import generate_password_hash, check_password_hash
import random
import ipaddress, re

app= Flask(__name__)
app.secret_key = "SuperSecretKeyAy"

def get_user_ipv4():
    if request.headers.get("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For").split(",")[0]
    else:
        ip = request.remote_addr
    return ip

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

@app.route("/")
def index():
    return """
    <h1>Welcome!</h1>
    <ul>
        <li><a href="/register">Register</a></li>
        <li><a href="/login">Login</a></li>
    </ul>    
        """

@app.route("/register", methods=["GET", "POST"])
def register():
    if (request.method == "POST"):
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        user_id = random.randint(0, 100000)
        user_role = "standard"
        hashed_p = generate_password_hash(password, method="scrypt", salt_length=16)

        if not is_valid_email(email):
            flash("Put in a valid email!")
            return redirect(url_for("register"))

        if not (6 <= len(username) <=30):
            flash("Your username has to be between 6 - 30 letters")
            return redirect(url_for("register"))
        
        if not (6 <= len(password) <=18):
            flash("Your password has to be between 6 - 18 letters")
            return redirect(url_for("register"))

        try:
            with open("account_data.json", "r") as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            data= []
            
        existing_ids = {user["id"]for user in data}
        while user_id in existing_ids:
            user_id = random.randint(0, 100000)

        ip = get_user_ipv4()

        if not ip:
            flash("Login attempt from non IPv4 address! Please try again")


        for user in data:
            if user["username"] == username:
                flash("Username is already in use please try again!")
                return redirect(url_for("register"))
        data.append({"id": user_id, "role":user_role, "username": username, "email": email, "password": hashed_p, "last_ip": ip})

        
        session["user"] = username
        session["user_id"] = user_id
        session["role"] = user_role


        with open("account_data.json", "w") as file:
            json.dump(data, file, indent=4)

        return redirect(url_for("dashboard"))
        
    return render_template("register.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if (request.method == "POST"):
        l_username = request.form.get("username")
        l_password = request.form.get("password")
        with open("account_data.json", "r") as file:
            data= json.load(file)
        ip = get_user_ipv4()
        for user in data:
            if user["username"] == l_username and check_password_hash(user["password"], l_password):
                
                session["user"] = user["username"]
                session["user_id"] = user["id"] 
                session["role"] = user.get("role", "user")



                return redirect("/dashboard")
        
        return "<h2>You were unsuccesful try again!</h2><a href='/register'"


    return render_template("login.html")



@app.route("/dashboard", methods=["POST", "GET"])
def dashboard():
    if "user" not in session:
        return redirect("/login")
    
    with open("account_data.json", "r") as file:
        data= json.load(file)
    


    if session.get("role") == "admin":
        return """<h2>Dashboard</h2><br>
        <a href='/admin'><button type='button'>Admin</button></a>
        <input id="b_logout" name="b_logout" type="submit" value="Log out">
        <script>
            document.getElementById("b_logout").addEventListener("click", function(){
                window.location.replace("/logout")
        });
        </script>"""
    else:
        return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect("/login")
    if session.get("role") == "admin":
        return render_template("admin.html", session=session)
    else:
        return redirect("/dashboard")


if __name__ == "__main__":
    app.run(debug=True)