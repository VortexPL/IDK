import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    symbols = db.execute("SELECT stock FROM history WHERE user_id=? AND type=? GROUP BY stock", session.get("user_id"), "buy")
    hlist = []
    for symbol in symbols:
        buy = db.execute("SELECT stock, SUM(shares) FROM history WHERE user_id=? AND type=? AND stock=? GROUP BY stock", session.get("user_id"), "buy", symbol["stock"])
        sell = db.execute("SELECT stock, SUM(shares) FROM history WHERE user_id=? AND type=? AND stock=? GROUP BY stock", session.get("user_id"), "sell", symbol["stock"])
        if not sell:
            hlist.append(buy[0])
        else:
            buy[0]["SUM(shares)"] -= sell[0]["SUM(shares)"]
            if int(buy[0]["SUM(shares)"]) != 0:
                hlist.append(buy[0])
    cash = db.execute("SELECT cash FROM users WHERE id=?", session.get("user_id"))
    total = 0
    for row in hlist:
        symbolist = lookup(row["stock"])
        row["name"] = symbolist["name"]
        row["price"] = float(symbolist["price"])
        total += row["price"] * int(row["SUM(shares)"])
    total += float(cash[0]["cash"])
    return render_template("index.html", stocks=hlist, total=int(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)
        symbolist = lookup(symbol)
        if not symbolist:
            return apology("must provide a valid symbol", 400)
        sharesn = request.form.get("shares")
        if not sharesn:
            return apology("must provide number of shares", 400)
        if isinstance(sharesn, float):
            return apology("must provide a valid number of shares", 400)
        if sharesn.isalpha():
            return apology("must provide number of shares", 400)
        if int(sharesn) < 1:
            return apology("must provide a positive number", 400)
        cash = db.execute("SELECT cash FROM users WHERE id=?", session.get("user_id"))
        cash = float(cash[0]["cash"])
        purchase = float(symbolist["price"]) * int(sharesn)
        if purchase > cash:
            return apology("you can not afford this purchase", 400)
        dt = datetime.datetime.now()
        cash -= purchase
        db.execute("UPDATE users SET cash=? WHERE id=?", cash, session.get("user_id"))
        db.execute("INSERT INTO history (user_id, stock, shares, price, type, date, time) VALUES (?, ?, ?, ?, ?, ?, ?)", session.get("user_id"), symbol, sharesn, symbolist["price"], "buy", dt.strftime("%Y-%m-%d"), dt.strftime("%X"))
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    history = db.execute("SELECT stock, shares, price, type, date, time FROM history WHERE user_id=? ORDER BY id DESC", session.get("user_id"))
    return render_template("history.html", history=history)

@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    if request.method == "POST":
        cash = db.execute("SELECT cash FROM users WHERE id=?", session.get("user_id"))
        cash = float(cash[0]["cash"])
        acash = request.form.get("cash")
        if not acash:
            return apology("provide a valid number", 400)
        if float(acash) <= 0:
            return apology("provide a positive number", 400)
        cash += float(acash)
        db.execute("UPDATE users SET cash=? WHERE id=?", cash, session.get("user_id"))
        return redirect("/cash")
    else:
        cash = db.execute("SELECT cash FROM users WHERE id=?", session.get("user_id"))
        cash = float("{:.2f}".format(cash[0]["cash"]))
        return render_template("cash.html", cash=cash)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)
        symbolist = lookup(symbol)
        if not symbolist:
            return apology("symbol must exist", 400)
        symbolist["price"] = int(symbolist["price"])
        symbolist["price"] = "{:.2f}".format(symbolist["price"])
        return render_template("quoted.html", quote=symbolist)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 400)
        if username.isdecimal():
            return apology("must provide a username with letters", 400)
        password = request.form.get("password")
        if not password:
            return apology("must provide password", 400)
        if len(password) < 5:
            return apology("your password must include atleast 5 characters", 400)
        if password.isalpha():
            return apology("your password must include numbers and/or symbols", 400)
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("must provide confirmation", 400)
        checkusername = db.execute("SELECT username FROM users WHERE username =?", username)
        if len(checkusername) == 1:
            return apology("this username already exists", 400)
        if not password == confirmation:
            return apology("password must match confirmation", 400)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if symbol == "":
            return apology("choose a stock", 400)
        shares = request.form.get("shares")
        if not shares:
            return apology("must provide number of shares", 400)
        if isinstance(shares, float):
            return apology("must provide a valid number of shares", 400)
        if int(shares) < 1:
            return apology("must provide a positive number of shares", 400)
        buy = db.execute("SELECT stock, SUM(shares) FROM history WHERE user_id=? AND type=? AND stock=? GROUP BY stock", session.get("user_id"), "buy", symbol)
        sel = db.execute("SELECT stock, SUM(shares) FROM history WHERE user_id=? AND type=? AND stock=? GROUP BY stock", session.get("user_id"), "sell", symbol)
        if not sel:
            buy = buy[0]
        else:
            buy[0]["SUM(shares)"] -= sel[0]["SUM(shares)"]
            if int(buy[0]["SUM(shares)"]) == 0:
                return apology("do not own any shares of that stock", 400)
            else:
                buy = buy[0]
        if int(buy["SUM(shares)"]) < int(shares):
            return apology("you do not own that many shares", 400)
        cash = db.execute("SELECT cash FROM users WHERE id=?", session.get("user_id"))
        cash = float(cash[0]["cash"])
        symbolist = lookup(symbol)
        sell = float(symbolist["price"]) * int(shares)
        dt = datetime.datetime.now()
        cash += sell
        db.execute("UPDATE users SET cash=? WHERE id=?", cash, session.get("user_id"))
        db.execute("INSERT INTO history (user_id, stock, shares, price, type, date, time) VALUES (?, ?, ?, ?, ?, ?, ?)", session.get("user_id"), symbol, shares, symbolist["price"], "sell", dt.strftime("%Y-%m-%d"), dt.strftime("%X"))
        return redirect("/")
    else:
        stocks = []
        symbols = db.execute("SELECT stock FROM history WHERE user_id=? AND type=? GROUP BY stock", session.get("user_id"), "buy")
        for symbol in symbols:
            buy = db.execute("SELECT stock, SUM(shares) FROM history WHERE user_id=? AND type=? AND stock=? GROUP BY stock", session.get("user_id"), "buy", symbol["stock"])
            sell = db.execute("SELECT stock, SUM(shares) FROM history WHERE user_id=? AND type=? AND stock=? GROUP BY stock", session.get("user_id"), "sell", symbol["stock"])
            if not sell:
                stocks.append(buy[0])
            else:
                buy[0]["SUM(shares)"] -= sell[0]["SUM(shares)"]
                if int(buy[0]["SUM(shares)"]) != 0:
                    stocks.append(buy[0])
        return render_template("sell.html", stocks=stocks)
