"""@author: Camesha Obi     
produces a website that validate emails
username, password inorder to view site"""
import logging#config import fileConfig
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin,login_required, LoginManager,login_user, current_user, logout_user
import forms# to avoid circular import


app = Flask(__name__)#cryptographic signature generated
app.config['SECRET_KEY'] = 'thisismysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
#data base
bcrypt = Bcrypt(app)
#protects password
login_manager = LoginManager(app)
login_manager.init_app(app)#assist with keeping unathorized users on login page
login_manager.login_view = 'login'
#assist with keeping unathorized users on login page
logging.basicConfig(filename='logger.log', level=logging.ERROR,\
     format='%(asctime)s:%(message)s')
#pylint: disable=no-member
class Users(db.Model, UserMixin):#mixin used by login manager for is_authorized
    """adding user information for db database"""
    __tablename__ = 'Users'#formating a table for database
    id = db.Column(db.Integer, primary_key=True)#numbers organized
    username = db.Column(db.String(20), unique=True, nullable=False)#nullable/not empty
    password = db.Column(db.String(20), nullable=False)#amount of character
    email = db.Column(db.String(120), unique=True, nullable=False)#must be different
    def __repr__(self):#debugging and testing
        return f'{self.username} : {self.password} : {self.email} '

@app.route('/register', methods=['GET','POST'])
def register():  # the company page
    """Where user signup"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = forms.RegistrationForm()
    if form.validate_on_submit():#instanciated, and accepts username data of the field
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user=Users(username=form.username.data,\
            email=form.email.data,password = hashed_password)#hashed_password)#protecting password
        db.session.add(user)#adding user to database
        db.session.commit()#writes the user to database
        flash(f'Account created succesfully for {form.username.data}', category='success')
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET','POST'])
def login():# the company page
    """Where user sign in """
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = forms.LoginForm()#is going to retun first username
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        unsuccesful = True
        logging.debug("login %s", unsuccesful )
        flash(f'login unsuccessful for {form.username.data}', category='danger')
    return render_template("login.html", form=form)

@app.route('/updatepass', methods=['GET','POST'])
@login_required
def updatepass():
    """Updating password while logged in"""
    form = forms.UpdatePassForm()
    if form.validate_on_submit():#instanciated, and accepts username data of the field
        hashed_password = bcrypt.generate_password_hash(form.newpassword.data).decode('utf-8')
        Users.password == hashed_password
        # user=Users(password = hashed_password)#hashed_password)#protecting password
        db.session.add(hashed_password)#password = hashed_password
        db.session.commit()#writes the user to database
        flash('Password succesfully updated ', category='success')
        return redirect(url_for('home'))
    flash('Password unsuccesful updated ', category='success')
    return render_template('login.html', form=form)

@login_manager.user_loader
def load_user(user_id):#assist authorization/keeping user out of webpages
    """Authorization assistance"""
    return Users.query.get(int(user_id))#if not logged in

@app.route('/')
@app.route('/base')
def base():
    """Ask if sign in or sign up"""
    return render_template("base.html")

@app.route('/home')
@login_required
def home():
    """Where you see top 5 billionairs"""
    return render_template("home.html")


@app.route('/about')  # the about page
@login_required
def about():
    """Where you see info on 5 billionairs"""
    return render_template("about.html")


@app.route('/company')
@login_required
def display():  # the company page
    """Where you see information on the companies"""
    return render_template("company.html")


@app.route("/logout")
def logout():
    """logging out user"""
    logout_user()
    return redirect(url_for('register'))

if __name__ == '__main__':
    app.run(debug=True)
