#https://stackoverflow.com/questions/34281873/how-do-i-split-flask-models-out-of-app-py-without-passing-db-object-all-over

from hello import db
# from hello import app
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
from flask_login import UserMixin
from datetime import datetime, date

# db = SQLAlchemy(app)
# migrate = Migrate(app, db)

# Create a DB Model: (UserMixin is part of flask-login)
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True) # gets assigned automatically, since primary key
    username = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(200), nullable=False) # max length=200, cannot be blank
    email = db.Column(db.String(120), nullable=False, unique=True) # must be unique
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    favorite_color = db.Column(db.String(120))
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute!') # shows error if something goes wrong

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):  # repr = 'representation'
        return '<Name %r>' % self.name

# Create a blog post model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    slug = db.Column(db.String(255)) # way to reference post in URL other than just using ID
