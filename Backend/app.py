from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from wtforms.validators import InputRequired
import requests
from alpha_vantage.timeseries import TimeSeries
from sqlalchemy.exc import IntegrityError
import logging
from forex_python.converter import CurrencyRates
from flask import render_template, request

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = '123456789'  # Change this to a secure key
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

logging.basicConfig(level=logging.DEBUG)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class FinancialInstrument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    symbol = db.Column(db.String(10), unique=True, nullable=False)
    price = db.Column(db.Float)



@app.route('/')
def hello():
    return 'Witaj w aplikacji HelpInvest!'

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('hello'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('hello'))

def get_latest_price(symbol):
    try:
        # Zastąp 'YOUR_API_KEY' własnym kluczem API finnhub.io
        finnhub_api_key = 'cm1l5c9r01qvthn7r6cgcm1l5c9r01qvthn7r6d0'
        url = f'https://finnhub.io/api/v1/quote?symbol={symbol}&token={finnhub_api_key}'
        response = requests.get(url)
        data = response.json()

        if 'c' in data:  # Sprawdź, czy klucz 'c' (cena) istnieje w odpowiedzi
            latest_price = data['c']
            return latest_price
        else:
            logging.warning(f'Failed to get the latest price for {symbol}. Skipping...')
            return None

    except Exception as e:
        logging.error(f'Failed to fetch data for {symbol}. Error: {str(e)}')
        return None
    

 def get_monthly_price(symbol):
    try:
        url = f'https://www.alphavantage.co/query?function=TIME_SERIES_MONTHLY&symbol={symbol}&apikey=DY6E5QMLMQBQ6MNN'
        r = requests.get(url)
        data = r.json()
    



@app.route('/financial_instruments/instrument.symbol')
def financial_instrument_details(instrument_id):
    instrument = FinancialInstrument.query.get_or_404(instrument_id)
    return render_template('instrument_details.html', title='Instrument Details', instrument=instrument)
    
@app.route('/financial_instruments', methods=['GET', 'POST'])
def financial_instruments():
    tickers = ['AAPL', 'GOOGL', 'MSFT', 'NFLX', 'META', 'AMZN', 'AMD', 'TSLA', 'INTC', 'NVDA']

    for ticker in tickers:
        try:
            logging.info(f'Fetching data for {ticker}')
            latest_price = get_latest_price(ticker)
            
            if latest_price is not None:
                instrument = FinancialInstrument(
                    name=f"{ticker} Corp.",
                    category="Technology",
                    description=f"Description for {ticker}",
                    symbol=ticker,
                    price=latest_price
                )

                db.session.add(instrument)
                db.session.commit()

                logging.info(f'Successfully added {ticker} to the database. Price: {latest_price}')
            else:
                logging.warning(f'Failed to get the latest price for {ticker}. Skipping...')

        except IntegrityError:
            db.session.rollback()
            logging.warning(f'Ticker {ticker} already exists in the database. Skipping...')

        except Exception as e:
            logging.error(f'Failed to fetch data for {ticker}. Error: {str(e)}')

    instruments = FinancialInstrument.query.filter_by(category="Technology").all()
    logging.info(f'Retrieved instruments from the database: {instruments}')

    return render_template('financial_instruments.html', title='Financial Instruments', instruments=instruments)

@app.route('/crypto_instruments/<int:instrument_id>')
def crypto_instrument_details(instrument_id):
    instrument = FinancialInstrument.query.get_or_404(instrument_id)
    return render_template('instrument_details.html', title='Crypto Instrument Details', instrument=instrument)

@app.route('/crypto_instruments', methods=['GET', 'POST'])
def crypto_instruments():
    cryptocurrencies = ['bitcoin', 'ethereum', 'ripple', 'litecoin', 'cardano', 'dogecoin', 'polkadot', 'uniswap', 'chainlink', 'stellar']

    for crypto_symbol in cryptocurrencies:
        try:
            # Sprawdź, czy ticker nie jest również na liście tickerów instrumentów akcyjnych
            if FinancialInstrument.query.filter_by(symbol=crypto_symbol.upper()).first() is None:
                # Użyj CoinGecko API do pobrania informacji o kryptowalucie
                api_url = f'https://api.coingecko.com/api/v3/simple/price?ids={crypto_symbol}&vs_currencies=usd'
                response = requests.get(api_url)
                data = response.json()

                # Dodaj log przed próbą pobrania danych z API
                logging.info(f'Fetching data for {crypto_symbol}')

                # Pobierz cenę z odpowiedzi API
                price = data[crypto_symbol]['usd']

                instrument = FinancialInstrument(
                    name=f"{crypto_symbol.capitalize()}",
                    category="Cryptocurrency",
                    description=f"Description for {crypto_symbol}",
                    symbol=crypto_symbol.upper(),
                    price=price
                )

                db.session.add(instrument)
                db.session.commit()

                # Dodaj log po dodaniu danych do bazy
                logging.info(f'Successfully added {crypto_symbol} to the database.')

            else:
                # Dodaj log w przypadku, gdy ticker już istnieje w bazie danych
                logging.warning(f'Crytpo symbol {crypto_symbol} already exists in the database. Skipping...')

        except IntegrityError:
            db.session.rollback()

            # Dodaj log w przypadku błędu IntegrityError
            logging.warning(f'Crytpo symbol {crypto_symbol} already exists in the database. Skipping...')

        except Exception as e:
            # Dodaj log w przypadku innych błędów
            logging.error(f'Failed to fetch data for {crypto_symbol}. Error: {str(e)}')

    crypto_instruments = FinancialInstrument.query.filter_by(category="Cryptocurrency").all()
    return render_template('crypto_instruments.html', title='Cryptocurrency Instruments', instruments=crypto_instruments)


@app.route('/forex_instruments/<int:instrument_id>')
def forex_instrument_details(instrument_id):
    instrument = FinancialInstrument.query.get_or_404(instrument_id)
    return render_template('instrument_details.html', title='Forex Instrument Details', instrument=instrument)

@app.route('/forex_instruments', methods=['GET', 'POST'])
def forex_instruments():
    # Waluty Forex
    forex_currencies = ['USD', 'EUR', 'JPY', 'GBP', 'AUD', 'CAD', 'CHF', 'NZD', 'SEK', 'NOK']

    # Pobierz kursy wymiany dla złotówki
    c = CurrencyRates()
    exchange_rates_to_pln = {currency: c.get_rate(currency, 'PLN') for currency in forex_currencies}

    for forex_currency in forex_currencies:
        try:
            # Sprawdź, czy waluta nie istnieje już w bazie danych
            if FinancialInstrument.query.filter_by(symbol=forex_currency).first() is None:
                # Użyj exchangeratesapi.io do pobrania kursu waluty
                api_url = f'https://open.er-api.com/v6/latest/{forex_currency}'
                response = requests.get(api_url)
                data = response.json()

                # Dodaj log przed próbą pobrania danych z API
                logging.info(f'Fetching data for {forex_currency}')

                # Pobierz kurs z odpowiedzi API
                price = 1.0 / data['rates'][forex_currency]  # Kurs bazowy na jednostkę

                # Przelicz cenę do złotówek
                price_pln = price * exchange_rates_to_pln[forex_currency]

                instrument = FinancialInstrument(
                    name=f"{forex_currency} Exchange Rate",
                    category="Forex",
                    description=f"Description for {forex_currency} Exchange Rate",
                    symbol=forex_currency,
                    price=price_pln  # Ustaw cenę w złotówkach
                )

                db.session.add(instrument)
                db.session.commit()

                # Dodaj log po dodaniu danych do bazy
                logging.info(f'Successfully added {forex_currency} to the database.')

            else:
                # Dodaj log w przypadku, gdy waluta już istnieje w bazie danych
                logging.warning(f'Forex currency {forex_currency} already exists in the database. Skipping...')

        except IntegrityError:
            db.session.rollback()

            # Dodaj log w przypadku błędu IntegrityError
            logging.warning(f'Forex currency {forex_currency} already exists in the database. Skipping...')

        except Exception as e:
            # Dodaj log w przypadku innych błędów
            logging.error(f'Failed to fetch data for {forex_currency}. Error: {str(e)}')

    forex_instruments = FinancialInstrument.query.filter_by(category="Forex").all()
    return render_template('forex_instruments.html', title='Forex Instruments', instruments=forex_instruments)


if __name__ == '__main__':
    app.run(debug=True)