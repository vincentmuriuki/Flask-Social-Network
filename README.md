
The UserMixin From Flask-Login
5:50 with Kenneth Love

There's no reason to do all of this work ourselves when projects like Flask-Login exist to do so much of it for us. Let's use the `UserMixin` mixin to add the necessary properties to our model so users can log in.

Import everything from the Peewee library. Create a new model named User. Give User an email attribute that is a CharField(). email should be unique.

Cryptographic Hashing with Flask-Bcrypt
6:50 with Kenneth Love

Letting users create accounts is great but until we responsibly store the passwords, we really shouldn't open the doors. We'll use the super-strong `bcrypt` library to hash their passwords before the store them so we know our data is secure.

Import the UserMixin from Flask-Login. Remember that Flask extensions usually have import paths that start with flask.ext.

pip install flask-bcrypt
Notes

    flask.ext.bcrypt - The path where Flask Bcrypt is available.
    generate_password_hash() - function to generate a hash from a string. Takes an optional number of rounds of hashing to use. More rounds always makes the process take longer.
    check_password_hash() - function to check a hash against a string to see if they match.

Challenge Task 2 of 3

Now create a function named set_password that takes a User and a string for their password. Hash the password, set the User.password attribute to the hashed password, and return the User.
from flask.ext.bcrypt import generate_password_hash
from flask.ext.bcrypt import check_password_hash

def set_password(User, password):
    generate_password_hash(password)
    User.password = generate_password_hash(password)
    return User

def validate_password(User, password):
    if check_password_hash(User.password, password):
        return True
    else:
        return True


Class Method
4:07 with Kenneth Love

Sometimes it just doesn't make sense to make an instance of a class before we call a method on it. Python gives us a decorator named `@classmethod` that allows us to create an instance of the class from inside of it. Let's see how to use this to make user creation easier.

@classmethod

Let's talk more about @classmethod. Let's make a class to represent an email.

class Email:
    to = None
    from = None
    subject = None
    content = None

If I want to make a new Email using the class constructor, that's easy. email = Email() and then fill in the attributes. Assuming there's a __init__() that handles setting the attributes, I can probably do that in one step.

But what if I want a method for immediately creating and sending the email? I either have to create an instance and then call .send() on the instance or I need a @classmethod way of generating one.

class Email:
    to = None
    from = None
    subject = None
    content = None

    @classmethod
    def create_and_send(cls, to, from, subject, content):
        cls(to=to, from=from, subject=subject, content=content).send()

This won't be a benefit to every class you create, but it's often a better way of approaching use cases where you don't need the class to hang around longer than needed to perform some action.


Add a @classmethod to User named new. It should take two arguments, email and password. The body of the method can be pass for now. Remember, @classmethods take cls as the first argument.
import datetime

from flask.ext.bcrypt import generate_password_hash
from flask.ext.login import UserMixin
from peewee import *

database = SqliteDatabase(':memory:')

class User(Model):
    email = CharField(unique=True)
    password = CharField(max_length=100)
    join_date = DateTimeField(default=datetime.datetime.now)
    bio = CharField(default='')
    
    class Meta:
        database = database
        
    @classmethod
    def new(cls, email, password):
        cls.create(
            email=email,
            password=generate_password_hash(password)
        )


Before and After Requests
4:27 with Kenneth Love

We often need to do things at the beginning of a request or at the end of one, before the response is sent back. In our case now, we need to connect to the database on the way in, and disconnect from it on the way out. Luckily, Flask provides two handy decorators for this.


Before and After Requests
4:27 with Kenneth Love

We often need to do things at the beginning of a request or at the end of one, before the response is sent back. In our case now, we need to connect to the database on the way in, and disconnect from it on the way out. Luckily, Flask provides two handy decorators for this.


Flask-WTF Forms
9:39 with Kenneth Love

Using code-based forms to create HTML forms and also provide data validation gives us two powerful tools for building our web application.



pip install flask-wtf

Flask-WTF docs

wtforms docs

Flask-WTF uses wtforms behind the scenes for the actual form, field, and widget creation.



Macros
4:19 with Kenneth Love

We don't want to have to type out all of the template code required to render forms every single time we render a form. Let's make a Jinja2 macro, or a template function, that'll handle this work for us.

New terms

    {% macro %} - A function in a template to repeat code on demand. Often really useful for things like form fields.

Note

If you're constantly getting a locked database, change your User.create_user method to the following:

@classmethod
    def create_user(cls, username, email, password, admin=False):
        try:
            with DATABASE.transaction():
                cls.create(
                    username=username,
                    email=email,
                    password=generate_password_hash(password),
                    is_admin=admin)
        except IntegrityError:
            raise ValueError("User already exists")

Create a macro named hide_email. It should take a User as an argument. Print out the email attribute of the User in the following format: t***@example.com for the email test@example.com. This will require splitting the email string and using a for loop.

from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    class User:
        email = None
    user = User()
    user.email = 'kenneth@teamtreehouse.com'
    return render_template('user.html', user=user)

{%- macro hide_email(user) -%}
  {#- Get the first letter of the email -#}
  {{user.email[0]}}
  {#- Get all the letters after the first, but before the @ -#}
  {%- for letter in user.email.split('@')[0][1:] -%}
    {{'*'}}
  {%- endfor -%}
  {#- Append the rest of the email on -#}
  {{ '@' + user.email.split('@')[1] }}
{%- endmacro -%}





Login View
6:17 with Kenneth Love

Now that users can sign up, we should let them sign in. Our `login()` view will be pretty straightforward, as will the template.


New terms

    login_user - Function to log a user in and set the appropriate cookie so they'll be considered authenticated by Flask-Login



from flask import Flask, g, render_template, flash
from flask.ext.login import LoginManager



Flask, Build a Social Network, Taking Names' section, Challenge: Form View

    Challenge Task 3 of 3

    Finally, update the register() view so that the form is validated on submission. If it's valid, use the models.User.new() method to create a new User from the form data and flash the message "Thanks for registering!". You'll need to import flash().


@app.route('/register', methods=('GET', 'POST'))
def register():
    form = forms.SignUpForm()
    if form.validate_on_submit():
        models.User.new(form.email.data, form.password.data)
        flash("Thanks for registering!")
    return render_template('register.html', form=form)



Post Model
4:05 with Kenneth Love

To let users make posts, we have to have a model to store the posts in. We'll also want to add some methods to our `User` model to make fetching posts easier.


New terms

    ForeignKeyField - A field that points to another database record.


Great! Now, add a ForeignKeyField to your LunchOrder model. Name it user. user should be related to the User model and the related_name should be "orders".

e

from flask.ext.bcrypt import generate_password_hash
from flask.ext.login import UserMixin
from peewee import *

DATABASE = SqliteDatabase(':memory:')


class User(UserMixin, Model):
    email = CharField(unique=True)
    password = CharField(max_length=100)
    join_date = DateTimeField(default=datetime.datetime.now)
    bio = CharField(default='')
    
    class Meta:
        database = DATABASE
    
    @classmethod
    def new(cls, email, password):
        cls.create(
            email=email,
            password=generate_password_hash(password)
        )
class LunchOrder(Model):
    order = TextField()
    date = DateField(datetime.datetime)
    user = ForeignKeyField(
    rel_model=User,
    related_name='orders')

def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User], safe=True)
    DATABASE.close()






Post Form and View
7:14 with Kenneth Love

Now that we can save posts in the database, let's create a form and view for capturing them from the user.



We assigned the database and the current user, from Flask Login, to the g object, Flask's global attribute that gets passed around to all of our views automatically, so now we can use it to get the current user.
Alert!

In this video and the others in this course, you'll see me using {{ current_user.is_authenticated() }}. At the time of filming, this was the correct way to use the is_authenticated() method on the UserMixin from flask-login. BUT, as is often the case in open source, things have changed. You'll now want to always use it as a property instead. So, use {{ current_user.is_authenticated }} instead. No parentheses!


Next, create a new view in lunch.py named order_lunch. Give it a route of /order and make sure it accepts both GET and POST methods. Make it return the rendered version of the lunch.html template.

lunch.py
from flask import Flask, g, render_template, flash, redirect, url_for
from flask.ext.bcrypt import check_password_hash
from flask.ext.login import LoginManager, login_user, current_user, login_required, logout_user

import forms
import models

app = Flask(__name__)
app.secret_key = 'this is our super secret key. do not share it with anyone!'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(userid):
    try:
        return models.User.select().where(
            models.User.id == int(userid)
        ).get()
    except models.DoesNotExist:
        return None


@app.before_request
def before_request():
    g.db = models.DATABASE
    g.db.connect()
    g.user = current_user
    

@app.after_request
def after_request(response):
    g.db.close()
    return response


@app.route('/register', methods=('GET', 'POST'))
def register():
    form = forms.SignUpInForm()
    if form.validate_on_submit():
        models.User.new(
            email=form.email.data,
            password=form.password.data
        )
        flash("Thanks for registering!") 
    return render_template('register.html', form=form)
  

@app.route('/login', methods=('GET', 'POST'))
def login():
    form = forms.SignUpInForm()
    if form.validate_on_submit():
        try:
            user = models.User.get(
                models.User.email == form.email.data
            )
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("You're now logged in!")
            else:
                flash("No user with that email/password combo")
        except models.DoesNotExist:
              flash("No user with that email/password combo")
    return render_template('register.html', form=form)

@app.route('/order',methods=('GET','POST'))
def order_lunch():
    form=forms.LunchOrderForm()
    if form.validate_on_submit():
        models.LunchOrder.create(  # Here you had LunchOrderForm.create
            user=g.user._get_current_object(),
            order=form.order.data,
            date=form.date.data  # Here you had form.order.data
            )

    return render_template('lunch.html',form=form)


@app.route('/secret')
@login_required
def secret():
    return "I should only be visible to logged-in users"

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
  

@app.route('/')
def index():
    return render_template('index.html')

models.py
import datetime

from flask.ext.bcrypt import generate_password_hash
from flask.ext.login import UserMixin
from peewee import *

DATABASE = SqliteDatabase(':memory:')


class User(UserMixin, Model):
    email = CharField(unique=True)
    password = CharField(max_length=100)
    join_date = DateTimeField(default=datetime.datetime.now)
    bio = CharField(default='')
    
    class Meta:
        database = DATABASE
    
    @classmethod
    def new(cls, email, password):
        cls.create(
            email=email,
            password=generate_password_hash(password)
        )


class LunchOrder(Model):
    order = TextField()
    date = DateField()
    user = ForeignKeyField(User, related_name="orders")

def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User], safe=True)
    DATABASE.close()

forms.py
from flask_wtf import Form
from wtforms import StringField, PasswordField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, Length


class SignUpInForm(Form):
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired(), Length(min=8)])
    
class LunchOrderForm(Form):
    order = TextAreaField(validators=[DataRequired()])
    date = DateField(validators=[DataRequired()])

# Pagination Docs
http://peewee.readthedocs.org/en/latest/peewee/playhouse.html?highlight=pagination#PaginatedQuery





Add a new view at /today that shows the current user's lunch order for today. It should render the "today.html" template. Don't worry about editing the template yet. Since this is about the current user, login should be required.


@app.route('/today')
@login_required
def today():
    order = models.LunchOrder.select().where(
        models.LunchOrder.date == datetime.date.today() &
        models.LunchOrder.user == g.user._get_current_object()
    ).get()
    return render_template('today.html', order=order)
