# pip install flask-wtf
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError # many other kinds of fields
from wtforms.validators import DataRequired, EqualTo, Length # there are many other kinds of validators, as well
from wtforms.widgets import TextArea

# Create LoginForm:
class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

# Password Form:
class PasswordForm(FlaskForm):
    email = StringField('What\'s Your Email?', validators=[DataRequired()])
    password_hash = PasswordField('Enter Your Password', validators=[DataRequired()])
    submit = SubmitField('Submit') # 'submit' button

# Create a Posts form
class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = StringField('Content', validators=[DataRequired()], widget=TextArea())
    author = StringField('Author', validators=[DataRequired()])
    slug = StringField('Slug', validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create a user form
class UserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    favorite_color = StringField('Favorite Color')
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Add\\Update User') # 'submit' button

# Create a form class
class NameForm(FlaskForm):
    name = StringField('What\'s Your Name?', validators=[DataRequired()])
    submit = SubmitField('Submit') # 'submit' button

    # https://flask-wtf.readthedocs.io/en/1.0.x/
	# BooleanField                  ## Validators
	# DateField                     # DataRequired
	# DateTimeField                 # Email
	# DecimalField                  # EqualTo
	# FileField                     # InputRequired
	# HiddenField                   # IPAddress  
	# MultipleField                 # Length    
	# FieldList                     # MacAddress
	# FloatField                    # NumberRange 
	# FormField                     # Optional
	# IntegerField                  # Regexp   
	# PasswordField                 # URL    
	# RadioField                    # UUID 
	# SelectField                   # AnyOf  
	# SelectMultipleField           # NoneOf          
	# SubmitField                     
	# StringField                     
	# TextAreaField                     


