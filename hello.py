from flask import Flask, render_template, request, redirect, url_for, flash # 'flash' used for messaging
# pip install flask-sqlalchemy
from flask_sqlalchemy import SQLAlchemy # needed for db access
from datetime import datetime, date
# pip install Flask-Migrate
from flask_migrate import Migrate # allows for database updates
from werkzeug.security import generate_password_hash, check_password_hash
# pip install flask_login
# handles login/out functions, but *does not* handle user registration
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
# import all forms from forms.py
# from forms import LoginForm, PostForm, UserForm, PasswordForm, NameForm
from forms import *

# Create a flask instance:
app = Flask(__name__)

# Add database to app:
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# Initialize the database:
db = SQLAlchemy(app)
migrate = Migrate(app, db)
# Equivalent to csrf_token
app.config['SECRET_KEY'] = 'my super secret key that no one is supposed to know'

from models import * # must come after database definitions

# JSON thing:
@app.route('/date')
def get_curret_date():
    # If you return a python dictionary, flask will turn it into JSON automatically
    return({'Date': date.today()})


# Flask login stuff
login_manager = LoginManager()
login_manager.init_app(app)  # because our app's name is 'app'
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Create Login page:
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)  # flask_login function
                flash('Login successful!')
                return redirect(url_for('dashboard'))
            else:
                flash('Username or Password is incorrect')
        else:
                flash('That user doesn\'t exist')
    return render_template('login.html', form=form)

# Create logout function
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('Logout Successful!')
    return redirect(url_for('login'))

# Create Dashboard page:
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UserForm()
    id = current_user.id # have to designate, since wasn't passed in URL
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.favorite_color = request.form['favorite_color']
        name_to_update.username = request.form['username']
        try:
            db.session.commit() # commits current values (from form) to DB
            flash('User Update Successful!')
            return render_template('dashboard.html', form=form, name_to_update=name_to_update)
        except:
            flash('Error - Update Unsuccessful!')
            return render_template('dashboard.html', form=form, name_to_update=name_to_update)
    else:
        return render_template('dashboard.html', form=form, name_to_update=name_to_update, id=id)


# Add page to list all posts
@app.route('/posts')
def posts():
    # Retrieve all posts from db
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template('posts.html', posts=posts)

# Display a specific post
@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    return render_template('post.html', post=post)

# Add Post page
@app.route('/add_post', methods=['GET', 'POST'])
@login_required # If user not logged-in, redirects to login page (can't change that)
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Posts(title=form.title.data, content=form.content.data, author=form.author.data, slug=form.slug.data)
        # Clear the form
        form.title.data = ''
        form.content.data = ''
        form.slug.data = ''
        form.author.data = ''
        # Add to database
        db.session.add(post)
        db.session.commit()
        flash('Blog Post Submitted Successfully!')
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html', posts=posts)
    return render_template('add_post.html', form=form)

# Edit Post
@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    form = PostForm()
    post = Posts.query.get_or_404(id)
    if form.validate_on_submit(): # if form has been submitted
        post.title = form.title.data
        post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data
        # Update database
        db.session.add(post)
        db.session.commit()
        flash('Post Has Been Updated!')
        return redirect(url_for('post', id=post.id))
    # If just loading the page
    form.title.data = post.title
    form.author.data = post.author
    form.slug.data = post.slug
    form.content.data = post.content
    return render_template('edit_post.html', form=form)

# Delete Post
@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash('Post Has Been Deleted!')
        # Redirect back the blog post list
        # Below is the same as the 'posts' page/function:
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html', posts=posts)
    except:
        flash('Error Deleting Post!')
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html', posts=posts)
        
# Create a route decorator
@app.route('/')
# def index():
#     return '<h1>Hello World!</h1>'
def index():
    return render_template('index.html')

@app.route('/user/<name>')
# passes 'name' from URL to function input to return render
def user(name):
    # return '<h1>Hello, {}!</h1>'.format(name)
    return render_template('user.html', user_name=name)

# Create name page
# Includes 'NameForm' class created above
@app.route('/name', methods=['GET', 'POST'])
def name():
    name = None # sets initial value of form variable
    form = NameForm()
    # Validate form
    if form.validate_on_submit():
        name = form.name.data # assign submission to 'name'
        form.name.data = '' # clear 'name' variable for next submission
        # notice that we don't have to pass this into the page via data dictionary
        flash('Form Submitted Successfully!')
    return render_template('name.html',
        name=name,
        form=form,
    )

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        # query the database, return all users with email submitted on form
        # and return the first one
        # ** If adding a new user, email shouldn't already be in database
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # hash the password
            hashed_pw = generate_password_hash(form.password_hash.data, 'sha256')
            # create new user from form data
            user = Users(username=form.username.data, name=form.name.data, email=form.email.data, favorite_color=form.favorite_color.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        form.favorite_color.data = ''
        form.password_hash.data = ''
        form.username.data = ''
        flash('User Successfully Added!')
    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html', form=form, name=name, our_users=our_users)

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.favorite_color = request.form['favorite_color']
        name_to_update.username = request.form['username']
        try:
            db.session.commit() # commits current values (from form) to DB
            flash('User Update Successful!')
            return render_template('update.html', form=form, name_to_update=name_to_update)
        except:
            flash('Error - Update Unsuccessful!')
            return render_template('update.html', form=form, name_to_update=name_to_update)
    else:
        return render_template('update.html', form=form, name_to_update=name_to_update, id=id)

@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User Deleted Successfully!')
        our_users = Users.query.order_by(Users.date_added)
        return render_template('add_user.html', form=form, name=name, our_users=our_users)

    except:
        flash('Error With User Deletion!')
        return render_template('add_user.html', form=form, name=name, our_users=our_users)

# Password test page
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
    email = None # sets initial value of form variable
    password = None
    pw_to_check = None
    passed = None  # correct password?
    form = PasswordForm()

    # Validate form
    if form.validate_on_submit():
        email = form.email.data 
        password = form.password_hash.data
        form.email.data = '' 
        form.password_hash.data = ''
        # lookup user by email address
        pw_to_check = Users.query.filter_by(email=email).first()
        #  check hashed password; returns true or false
        passed = check_password_hash(pw_to_check.password_hash, password)
        print(passed)
    return render_template('test_pw.html',
        email=email,
        password=password,
        pw_to_check = pw_to_check,
        passed = passed,
        form=form,
    )




# Create custom error pages:
# Invalid URL:
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

############################## MODELS ###################################

# Create a DB Model: (UserMixin is part of flask-login)
# class Users(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True) # gets assigned automatically, since primary key
#     username = db.Column(db.String(20), nullable=False)
#     name = db.Column(db.String(200), nullable=False) # max length=200, cannot be blank
#     email = db.Column(db.String(120), nullable=False, unique=True) # must be unique
#     date_added = db.Column(db.DateTime, default=datetime.utcnow)
#     favorite_color = db.Column(db.String(120))
#     password_hash = db.Column(db.String(128))

#     @property
#     def password(self):
#         raise AttributeError('Password is not a readable attribute!') # shows error if something goes wrong

#     @password.setter
#     def password(self, password):
#         self.password_hash = generate_password_hash(password)

#     def verify_password(self, password):
#         return check_password_hash(self.password_hash, password)

#     def __repr__(self):  # repr = 'representation'
#         return '<Name %r>' % self.name

# # Create a blog post model
# class Posts(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(255))
#     content = db.Column(db.Text)
#     author = db.Column(db.String(255))
#     date_posted = db.Column(db.DateTime, default=datetime.utcnow)
#     slug = db.Column(db.String(255)) # way to reference post in URL other than just using ID

