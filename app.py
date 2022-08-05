import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

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
db = SQL("sqlite:///stocks.db")

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


def get_stock_info(id):

    # Select list of stock symbols associated with user (sort according to shares)
    stocks = db.execute("SELECT symbol FROM stocks WHERE user_id = ? ORDER BY shares DESC" , id)
    symbols = [stock['symbol'] for stock in stocks]

    # Lookup for each symbol
    stocks_info = lookup(symbols)

    # Add additional info for each stock
    for stock in stocks_info:
        stock["shares"] = db.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", id, stock['symbol'])[0]['shares']
        stock["worth"] = stock["price"] * stock["shares"]

    return stocks_info


def get_cash(id):
    return db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]


##
### Routes
##

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]
    if not user_id:
        return redirect("/login")

    # Get user's cash
    cash = get_cash(user_id)

    # Get stock info for that user
    stocks = get_stock_info(user_id)

    total_stock_worth = 0
    for stock in stocks:
        total_stock_worth += stock["worth"]

    return render_template("index.html", stocks=stocks, cash=cash, total_stock_worth=total_stock_worth)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    # Render html page to quote for stocks
    if request.method == "GET":
        return render_template("buy.html")

    # Show stocks if quoted via POST
    if request.method == "POST":

        # Get stock symbol and no.of shares
        symbol = request.form.get("symbol")
        shares_bought = request.form.get("shares")
        user_id = session["user_id"]

        # Ensure correct symbol is used
        stock = lookup([symbol])[0]
        if not stock:
            return apology("Invalid Stock Symbol", 400)

        # Ensure that correct shares were bought
        try:
            shares_bought = int(shares_bought)
        except (ValueError, TypeError):
            return apology("Invalid Share Number", 400)
        if shares_bought <= 0:
            return apology("Invalid Share Number", 400)

        # Get the cash the buyer has
        cash = get_cash(user_id)

        # Render apology if cash not enough to buy stocks
        cost = stock["price"] * shares_bought
        if cash < cost:
            return apology("Not enough cash")

        # Update Database
        symbol = symbol.strip().upper()
        db.execute(
            "INSERT INTO transactions (user_id, symbol, purchased, date, sold)       \
             VALUES (?, ?, ?, ?, ?)", user_id, symbol, shares_bought, datetime.now(), 0
             )

        # Decrease cash in hand
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - cost, user_id)

        # Increase existing shares or create new share records in stocks table
        row = db.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if row == []:
            db.execute("INSERT INTO stocks (user_id, symbol, shares) VALUES (?, ?, ?)", user_id, symbol, shares_bought)
        else:
            curr_shares = row[0]['shares']
            db.execute("UPDATE stocks SET shares = ? WHERE user_id = ? AND symbol = ?", shares_bought + curr_shares, user_id, symbol)

        flash("Bought!")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    # Get records of transactions
    rows = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC", user_id)

    transactions = []
    # Go through list of dicts and collect useful info
    for row in rows:
        d = {}
        d['symbol'] = row['symbol']
        d['date'] = row['date']

        if row['purchased'] == 0:
            d['status'] = 'Sold'
            d['shares'] = row['sold']
        else:
            d['status'] = 'Purchased'
            d['shares'] = row['purchased']

        transactions.append(d)

    return render_template("history.html", transactions=transactions)


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
        if not request.form.get("password"):
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

    # Render html page to quote for stocks
    if request.method == "GET":
        return render_template("quote.html")

    # Show stocks if quoted via POST
    if request.method == "POST":

        # Get stock symbol
        symbol = request.form.get("symbol")
        # return f"{symbol}"

        # Ensure correct symbol is used
        stock = lookup([symbol])[0]
        if not stock:
            return apology("Stock Symbol Not Found", 400)

        # Show stock info
        return render_template("quoted.html", stock=stock)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    session.clear()

    # Just render the HTML page if requested using GET
    if request.method == "GET":
        return render_template("register.html")

    # Register user if requested using POST
    if request.method == "POST":

        # Get user info
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate registration
        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure that username was unique(not already taken)
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) != 0:      # Username already registered
            return apology("Username not available")

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        elif not confirmation or confirmation != password:
            return apology("passwords do not match", 400)

        # Register user
        hash = generate_password_hash(password)
        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, hash)

        # Redirect to stocks page
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]
    stocks = get_stock_info(user_id)

    # if route opened via GT:
    if request.method == "GET":
        if stocks == []:
            return apology("No Stocks Owned", 403)

        return render_template("sell.html", stocks=stocks)

    # if route opened via POT:
    if request.method == "POST":

        # Get stock symbol and no.of shares
        symbol = request.form.get("symbol")
        shares_sold = request.form.get("shares")

        # Check if symbol was correct and user had that symbol
        # Retrieve list of symbols
        rows = db.execute("SELECT symbol FROM stocks WHERE user_id = ?", user_id)
        symbols = [d['symbol'] for d in rows]

        if not symbol or not symbol in symbols or not lookup([symbol])[0]:
            return apology("Invalid Stock", 400)

        # Ensure that correct shares were being sold
        try:
            shares_sold = int(shares_sold)
        except (ValueError, TypeError):
            return apology("Invalid shares", 400)
        if shares_sold <= 0:
            return apology("Invaid Shares", 400)

        if symbol not in symbols:
            return apology("You don't have that stock", 403)


        # Ensure that user has enough shares
        curr_shares = db.execute("SELECT shares FROM stocks WHERE user_id = ? and symbol = ?", user_id, symbol)[0]["shares"]
        if curr_shares < shares_sold:
            return apology("Not enough stocks")

        # Get the cash the buyer has
        cash = get_cash(user_id)

        # Update sales record
        db.execute(
            "INSERT INTO transactions (user_id, symbol, sold, date, purchased)      \
             VALUES (?, ?, ?, ?, ?)", user_id, symbol, shares_sold, datetime.now(), 0
             )

        # Increase cash
        print(type(symbol))

        sale = lookup([symbol])[0]["price"] * shares_sold
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + sale, user_id)

        # Decrease shares from stock table (delete record if 0)
        rem_shares = curr_shares - shares_sold
        if rem_shares == 0:
            db.execute("DELETE FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol)
        else:
            db.execute("UPDATE stocks SET shares = ? WHERE user_id = ? AND symbol = ?", rem_shares, user_id, symbol)

        flash("Sold")
        return redirect("/")



@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    user_id = session["user_id"]

    # If user changed his username or password
    if request.method == "POST":

        # Know what the user wanted to change
        option = request.form.get("option")
        print("The option that user wantd to change is ", option)

        if option == "username":

            # User Changed username
            new_name = request.form.get("new_username")
            if not new_name:
                return apology("must provide username", 403)

            db.execute("UPDATE users SET username = ? WHERE id = ?", new_name, user_id)


        elif option == 'password':

            # User Changed password
            # Validate curr_password and Check hashes
            curr_pass = request.form.get("curr_pass")
            curr_hash = db.execute("SELECT hash FROM users WHERE id = ?", user_id)[0]['hash']

            print(curr_pass)
            print(check_password_hash(curr_pass, curr_hash))
            if not curr_pass or not check_password_hash(curr_hash, curr_pass):
                return apology("Incorrect existing password")

            # Validate new_password
            new_pass = request.form.get("new_pass")
            confirmation = request.form.get("confirmation")

            # Ensure new password was given
            if not new_pass:
                return apology("must provide new password", 403)

            elif not confirmation or confirmation != new_pass:
                return apology("passwords do not match", 403)

            # Update password
            hash = generate_password_hash(new_pass)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, user_id)

        return redirect('/')


    # Define a dictionary to store profile info
    profile = dict()

    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
    purchase_count = db.execute("select count(user_id) from transactions where user_id = ? AND sold = 0", user_id)[0]['count(user_id)']
    share_count = db.execute("SELECT SUM(shares) FROM stocks WHERE user_id = ?", user_id)[0]['SUM(shares)']

    # find purchase streak
    rows = db.execute("select * from transactions where user_id = ? order by date", user_id)

    streaks = []
    streak = 0
    purchases = [d['purchased'] for d in rows]
    for i in purchases:
        if i == 0:
            streaks.append(streak)
            streak = 0
        else:
            streak += 1

    # Append final streak
    streaks.append(streak)

    if purchases != []:
        streak = max(streaks)

    profile['username'] = username
    profile['purchase_count'] = purchase_count
    profile['share_count'] = share_count
    profile['streak'] = streak

    return render_template("profile.html", profile=profile)


# I added something
