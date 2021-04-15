from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators, IntegerField, DateField, SubmitField
from passlib.hash import sha256_crypt
from functools import wraps
import mysql.connector

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '123456'
app.config['MYSQL_DB'] = 'Zlash'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)


# home page
@app.route('/')
def index():
    return render_template('home.html')


# about page
@app.route('/about')
def about():
    return render_template('about.html')


# contact us page
@app.route('/contactus')
def contactus():
    return render_template('contactus.html')


class RegisterForm(Form):
    First_Name = StringField('First_Name')
    Last_Name = StringField('Last_Name')
    Email = StringField('Email')
    Phone_Number = IntegerField('Phone_Number')
    DOB = DateField('DOB', format='%d-%m-%Y')
    Username = StringField('Username')
    Password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('confirm Password')


# register entrepreneur page route
@app.route('/register_et', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        First_Name = form.First_Name.data
        Last_Name = form.Last_Name.data
        Email = form.Email.data
        Phone_Number = form.Phone_Number.data
        DOB = form.DOB.data
        Username = form.Username.data
        Password = sha256_crypt.encrypt(str(form.Password.data))

        cur = mysql.connection.cursor()

        cur.execute(
            "INSERT INTO et(First_Name, Last_Name, Email, Phone_Number, DOB, Username, Password) VALUES(%s, %s, %s, %s, %s, %s, %s)",
            (First_Name, Last_Name, Email, Phone_Number, DOB, Username, Password))

        mysql.connection.commit()

        cur.close()

        flash('You are now registered and can log in ')

        return redirect(url_for('register'))
    return render_template('register_et.html', form=form)


# register investor page route
@app.route('/register_iv', methods=['GET', 'POST'])
def registeriv():  # this is being called in url_for
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        First_Name = form.First_Name.data
        Last_Name = form.Last_Name.data
        Email = form.Email.data
        Phone_Number = form.Phone_Number.data
        DOB = form.DOB.data
        Username = form.Username.data
        Password = sha256_crypt.encrypt(str(form.Password.data))

        cur = mysql.connection.cursor()

        cur.execute(
            "INSERT INTO iv(First_Name, Last_Name, Email, Phone_Number, DOB, Username, Password) VALUES(%s, %s, %s, %s, %s, %s, %s)",
            (First_Name, Last_Name, Email, Phone_Number, DOB, Username, Password))

        mysql.connection.commit()

        cur.close()

        flash('You are now registered and can log in ')

        return redirect(url_for('registeriv'))
    return render_template('register_iv.html', form=form)


# register public page route
@app.route('/register_pe', methods=['GET', 'POST'])
def registerpe():  # this is being called in url_for
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        First_Name = form.First_Name.data
        Last_Name = form.Last_Name.data
        Email = form.Email.data
        Phone_Number = form.Phone_Number.data
        DOB = form.DOB.data
        Username = form.Username.data
        Password = sha256_crypt.encrypt(str(form.Password.data))

        cur = mysql.connection.cursor()

        cur.execute(
            "INSERT INTO pe(First_Name, Last_Name, Email, Phone_Number, DOB, Username, Password) VALUES(%s, %s, %s, %s, %s, %s, %s)",
            (First_Name, Last_Name, Email, Phone_Number, DOB, Username, Password))

        mysql.connection.commit()

        cur.close()

        flash('You are now registered and can log in ')

        return redirect(url_for('registerpe'))
    return render_template('register_pe.html', form=form)


@app.route('/login_et', methods=['GET', 'POST'])
def login_et():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM et WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['Password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard_et'))
            else:
                error = 'Invalid login'
                return render_template('login_et.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login_et.html', error=error)

    return render_template('login_et.html')


@app.route('/login_iv', methods=['GET', 'POST'])
def login_iv():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM iv WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['Password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in')
                return redirect(url_for('dashboard_iv'))
            else:
                error = 'Invalid login'
                return render_template('login_iv.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login_iv.html', error=error)

    return render_template('login_iv.html')


@app.route('/login_pe', methods=['GET', 'POST'])
def login_pe():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM pe WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['Password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in')
                return redirect(url_for('dashboard_pe'))
            else:
                error = 'Invalid login'
                return render_template('login_pe.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login_pe.html', error=error)

    return render_template('login_pe.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('index'))

    return wrap


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out')
    return redirect(url_for('index'))


@app.route('/dashboardet')
def dashboard_et():
    return render_template('dashboard_et.html')


@app.route('/dashboardiv')
def dashboard_iv():
    return render_template('dashboard_iv.html')


@app.route('/dashboardpe')
def dashboard_pe():
    return render_template('dashboard_pe.html')


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
