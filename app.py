from flask import Flask, request, g, make_response, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_moment import Moment
from flask_httpauth import HTTPTokenAuth, HTTPBasicAuth
import secrets
from datetime import datetime as dt, timedelta
from functools import wraps
import os

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
db = SQLAlchemy()
migrate = Migrate()
moment = Moment()
token_auth = HTTPTokenAuth()
basic_auth = HTTPBasicAuth()

##---------- Database ----------##
class Config():
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
##---------- Database ----------##

##---------- Database Information ----------##
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    last_name =  db.Column(db.String)
    email =  db.Column(db.String, unique=True, index=True)
    password =  db.Column(db.String)
    created_on = db.Column(db.DateTime, default=dt.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    token = db.Column(db.String, index=True, unique=True)
    token_exp = db.Column(db.DateTime)

    ##---------- Token Methods ----------##
    def get_token(self, exp=86400):
        current_time = dt.utcnow()
        if self.token and self.token_exp > current_time + timedelta(seconds=60):
            return self.token
        self.token = secrets.token_urlsafe(32)
        self.token_exp = current_time + timedelta(seconds=exp)
        self.save()
        return self.token

    def revoke_token(self):
        self.token_exp = dt.utcnow() - timedelta(seconds=61)
    
    @staticmethod
    def check_token(token):
        user  = User.query.filter_by(token=token).first()
        if not user or user.token_exp < dt.utcnow():
            return None
        return user
    ##---------- Token Methods ----------##

    ##---------- User Methods ----------##
    def __repr__(self):
        return f'<User: {self.email} | {self.id}>'

    def __str__(self):
        return f'<User: {self.email} | {self.first_name} {self.last_name}>'

    def from_dict(self, data):
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email=data['email']
        self.password = self.hash_password(data['password'])
        self.icon = data['icon']

    def save(self):
        db.session.add(self) 
        db.session.commit()

    def to_dict(self):
        return {
            'id':self.id,
            'first_name':self.first_name,
            'last_name':self.last_name,
            'email':self.email,
            'created_on':self.created_on,
            'icon':self.icon,
            'is_admin':self.is_admin,
            'token':self.token
        }

class Book(db.Model):
    book_id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String)
    author = db.Column(db.String)
    pages = db.Column(db.Integer)
    summary = db.Column(db.String)
    image = db.Column(db.String)

    def __repr__(self):
        return f'<Post: {self.id} | {self.body[:15]}>'

    def edit(self, new_title):
        self.title=new_title

    def save(self):
        db.session.add(self) 
        db.session.commit() 
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        return {
            'book_id': self.book_id,
            'title': self.title,
            'author': self.author,
            'pages ': self.pages,
            'summary': self.summary,
            'image': self.image
        }
##---------- Database Information ----------##

##---------- Auth Information ----------##

@token_auth.verify_token
def verify_token(token):
    user = User.check_token(token) if token else None
    g.current_user = user
    return user

@basic_auth.verify_password
def verify_password(email, password):
    user = User.query.filter_by(email=email).first()
    if user is None:
        return False
    g.current_user = user
    return user.check_hashed_password(password)

##---------- Auth Information ----------##

##---------- Helpers ----------##

def require_admin(f, *args, **kwargs):
    @wraps(f)
    def check_admin(*args, **kwargs):
        if not g.current_user.is_admin:
            abort(403)
        else:
            return f(*args, **kwargs)
    return check_admin

##---------- Helpers ----------##

##---------- /login ----------##
# GET => Returns User info (not password) along with the User Token
@app.get('/login')
@basic_auth.login_required()
def get_login():
    user = g.current_user
    token = user.get_token()
    return make_response({"token": token, **user.to_dict()}, 200)
##---------- /login ----------##

##---------- /user ----------##
# POST => Register a User
# PUT => Edit a user by id
# DELETE => Remove a User by id
    # "first_name" = "String"
    # "last_name" =  "String"
    # "email" =  "String"
    # "password" =  "String"
    # "created_on" = "DateTime"
    # "is_admin" = "Boolean"
    
@app.post('/user/<int:id>')
@token_auth.login_required()
@require_admin
def register_user(id):
    new_user_dict = request.get_json()
    if not all(key in new_user_dict for key in ('first_name', 'last_name', 'email', 'password', 'created_on', 'is_admin')):
        abort(404)
    new_user = User()
    new_user.from_dict(new_user_dict)
    new_user.save()
    return make_response(f"User {new_user.first_name} {new_user.last_name} has been created with id: {new_user.id}", 200)

@app.put('/user/<int:id>')
@token_auth.login_required()
@require_admin
def put_user(id):
    user_dict = request.get_json()
    user = User.query.get(id)
    if not user:
        abort(404)
    user.from_dict(user_dict)
    user.save()
    return make_response(f"User {user.id} has been udpated", 200)

@app.delete('/user/<int:id>')
@token_auth.login_required()
@require_admin
def delete_user(id):
    user_to_delete = User.query.get(id)
    if not user_to_delete:
        abort(404)
    user_to_delete.delete()
    return make_response(f"User with id {id} has been deleted", 200)

##---------- /book ----------##
# /book
# GET => Return a list of all Books
# GET => Return book info for book by id
# POST => Creates a new Book 
# PUT => Edits a Book by id
# DELETE => Delete a Book by id

# GET => Return a list of all Books
@app.get('/book')
@token_auth.login_required()
def get_book():
    books = Book.query.all()
    book_dicts = [book.to_dict() for book in books]
    return make_response({"books": book_dicts}, 200)

# GET => Return book info for book by id
@app.get('/book/<int:id>')
@token_auth.login_required()
def get_book_by_id(id):
    book = Book.query.get(id)
    if not book:
        abort(404)
    book_dict = book.to_dict()
    return make_response(book_dict, 200)
    
# POST => Creates a new Book 
    # "title" = "String"
    # "author" = "String"
    # "pages" = "Integer"
    # "summary" = "String"
    # "image" = "String"

@app.post('/book')
@token_auth.login_required()
@require_admin
def post_book():
    book_dict = request.get_json()
    if not all(key in book_dict for key in ('title', 'author', 'pages', 'summary', 'image')):
        abort(404)
    book = Book()
    book.from_dict()
    book.save()
    return make_response(f"Book {book.title} was created with an id {book.id}", 200)


# PUT => Edits a Book by id
@app.put('/book/<int:id>')
@token_auth.login_required()
@require_admin
def put_book(id):
    book_dict = request.get_json()
    book = Book.query.get(id)
    if not book:
        abort(404)
    book.from_dict(book_dict)
    book.save()
    make_response(f"Book {book.title} with ID {book.id} has been updated", 200)

# DELETE => Delete a Book by id
@app.delete('/item/<int:id>')
@token_auth.login_required()
@require_admin
def delete_book(id):
    book_to_delete = Book.query.get(id)
    if not book_to_delete:
        abort(404)
    book_to_delete.delete()
    return make_response(f"Book with id: {id} has been removed",200)

if __name__ == "__main__":
    app.run(debug=True)