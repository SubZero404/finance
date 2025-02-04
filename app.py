import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    """Show portfolio of stocks"""
    user_id = session['user_id']

    stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING total_shares > 0",
                        user_id = user_id)

    cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = user_id)[0]['cash']

    grand_total = cash

    for stock in stocks:
        quote = lookup(stock['symbol'])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["value"] = stock["price"] * stock["total_shares"]
        grand_total += stock["value"]

    return render_template('index.html', stocks = stocks, cash = cash, grand_total = grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        user_id = session['user_id']
        symbol = request.form.get('symbol').upper()
        shares = request.form.get('shares')
        if not symbol or not shares or int(shares) <= 0:
            return apology("Please enter symbol and shares", 400)
        
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid Symbol", 400)
        
        price = quote['price']
        total_price_of_shares_cost = price * int(shares)
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = user_id)[0]['cash']

        if cash < total_price_of_shares_cost:
            return apology("No enough cash")
        
        db.execute("UPDATE users SET cash = cash - :shares_cost WHERE id = :user_id",
                   shares_cost = total_price_of_shares_cost, user_id = user_id)
        
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                   user_id = user_id, symbol = symbol, shares = shares, price = price)
        
        flash(f"Bought {shares} shares of {symbol} for {usd(total_price_of_shares_cost)}")
        return redirect('/')
        
    return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
        symbol = request.form.get('symbol')
        if not symbol:
            return apology("Please enter quote!", 400)
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid Symbol", 400)
        return render_template('quote.html', quote = quote)
        
    return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()

    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        if not username:
            return apology("Please enter username", 400)
        elif not password:
            return apology("Please enter password", 400)
        elif not confirm_password:
            return apology("Please enter confirm password", 400)
        elif confirm_password != password:
            return apology("confrim password need to be same with password!", 400)
        
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("username already exits!", 400)
        
        user_id = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))

        session["user_id"] = user_id

        return redirect('/')
    return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session['user_id']

    stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING total_shares > 0",
                            user_id = user_id)

    if request.method == "POST":
        symbol = request.form.get('symbol').upper()
        shares = int(request.form.get('shares'))
        
        if not symbol or not shares or shares <= 0:
            return apology("Please enter symbol and shares", 400)
        
        for stock in stocks:
            if stock['symbol'] == symbol:
                if stock['total_shares'] < shares:
                    return apology("Not enough shares", 400)
                quote = lookup(symbol)
                if not quote:
                    return apology("Invalid Symbol", 400)
                price = quote['price']
                total_sale_price = price * shares

                db.execute("UPDATE users SET cash = cash + :total_sale_price WHERE id = :user_id",
                        total_sale_price = total_sale_price, user_id = user_id)
                
                db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                        user_id = user_id, symbol = symbol, shares = -shares, price = price)
                
                flash(f"Sold {shares} shares of {symbol} for {usd(total_sale_price)}")
                return redirect('/')
        
        return apology("This stock is not found in your account!", 400)
    return render_template('sell.html', stocks = stocks)
