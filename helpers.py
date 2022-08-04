import os
import urllib.parse
import asyncio
import aiohttp
import platform

from flask import redirect, render_template, session
from functools import wraps



def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbols):
    """Look up quote for symbol."""
    api_key = os.environ.get("API_KEY")
    stocks_info = list()

    def lookup_tasks(session, symbols):
        tasks = []
        for symbol in symbols:
            url = f"https://cloud.iexapis.com/stable/stock/{urllib.parse.quote_plus(symbol)}/quote?token={api_key}"
            tasks.append(asyncio.create_task(session.get(url)))

        return tasks

    async def lookup_symbols(symbols):
        async with aiohttp.ClientSession() as session:
            tasks = lookup_tasks(session, symbols)
            responses = await asyncio.gather(*tasks)

            for response in responses:
                quote = await response.json()
                symbol = quote['symbol']

                stocks_info.append({
                    "name": quote["companyName"],
                    "price": float(quote["latestPrice"]),
                    "symbol": symbol
                })

    # Run coroutine at once
    if platform.system()=='Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(lookup_symbols(symbols))

    return stocks_info

    
def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"



