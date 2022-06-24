"""Keeping forms together for registration and logging in"""
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, BooleanField
import wtforms.validators
import myapp


REG = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{12,20}$"
#password complexity
pat = re.compile(REG)

class RegistrationForm(FlaskForm):
    """Validating registration information"""#requires info, no less than 12 no greater than 20
    username = StringField(label='Username', validators=[wtforms.validators.DataRequired(),\
        wtforms.validators.Length(min=12, max=20)])
    email = StringField(label='Email', validators=[wtforms.validators.DataRequired(),\
        wtforms.validators.Email()])
#requires info, needs to be in this format,no les than 12 characters
    password = PasswordField(label='Password',\
         validators=[wtforms.validators.DataRequired(),\
            wtforms.validators.regexp(regex=pat,\
                message='At least one uppercase,lowercase,number and special character'),\
                    wtforms.validators.Length(min=12,max=20,\
                        message='password must be 12 to 20 characters long.')])
    confirm_password = PasswordField(label='Confirm Password',\
         validators=[wtforms.validators.DataRequired(),\
             wtforms.validators.EqualTo('password',\
                 message='Passwords must match')])
    submit = SubmitField(label='Sign up')#button
    # checks if username exist and unique compared to database

    def validate_username(self,username):
        """Validation for username against database"""
        user = myapp.Users.query.filter_by(username=username.data).first()
        if user:#else throws error
            raise ValidationError(
                "That username currently exists. Please choose a different one")
    def validate_email(self,email):#checks if email exist and unique
        """Validation for email against database"""
        user = myapp.Users.query.filter_by(email=email.data).first()
        if user:#else throws error
            raise ValidationError(
                "That email currently exists. Please choose a different one")
    def validate_password(self,password):
        """Validation for username against database"""
        # user = myapp.Users.query.filter_by(password=password.data).first()
        files = open('CommonPassword.txt', 'r')
        if any (password.data == file.strip() for file in files):
            raise ValidationError('This password is too common!')

class LoginForm(FlaskForm):
    """Validating login information"""#needs to be the same as signup, validator will send error
    username = StringField(label='Username', validators=[wtforms.validators.DataRequired(),\
        wtforms.validators.Length(min=12, max=20)])
    #data required, length check
    password = PasswordField(label='Password',
                             validators=[wtforms.validators.DataRequired(),
                                         wtforms.validators.Length(min=12, max=20)])
    remember = BooleanField('Remember Me')
    #data required
    submit = SubmitField(label='Login')#getting the user info and if bad info

class UpdatePassForm(FlaskForm):
    """Allow user to reset password"""
    newpassword = PasswordField(label='New Password',
                             validators=[wtforms.validators.DataRequired(),\
                                 wtforms.validators.regexp(regex=pat,message='At least\
                                      one uppercase,lowercase,number and special character'),\
                                          wtforms.validators.Length(min=12, max=20)])
    confirm_new_password = PasswordField(label='Confirm Password',\
         validators=[wtforms.validators.DataRequired(),\
             wtforms.validators.EqualTo('newpassword',\
                 message='Passwords must match')])
    remember = BooleanField('Remember Me')
    #data required
    submit = SubmitField("Update Password")#getting the user info and if bad info

    def validate_password(self,password):
        """Validation for username against database"""
        files = open('CommonPassword.txt','r')
        if any (password.data == file.strip() for file in files):
            raise ValidationError('This password is too common!')
