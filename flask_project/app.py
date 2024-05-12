from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import random

app = Flask(__name__)

app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        N = 6
        images_ = random.sample(range(10, 46), N * N)
        images = [images_[i:i + N] for i in range(0, N * N, N)]
        return render_template('signup.html', images=images)
    elif request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        if(request.form.get('row') and request.form.get('column')):
            row = request.form.get('row')
            col = request.form.get('column')
            password = row + col
            print(password)
        else:
            password_1 = sorted(request.form.getlist('password'))
            password_1 = ''.join(map(str, password_1))
            if len(password_1) < 8:
                flash("password must be minimum 4 selections")
                return redirect(url_for('signup'))
            else:
                password = password_1

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))

        new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        N = 6
        images_ = random.sample(range(10, 46), N * N)
        images = [images_[i:i + N] for i in range(0, N * N, N)]
        return render_template('login.html', images=images)
    elif request.method == 'POST':
        email = request.form.get('email')
        if(request.form.get('row-column')):
            password = request.form.get('row-column')
            print(password)
        else:
            password_1 = sorted(request.form.getlist('password'))
            password_1 = ''.join(map(str, password_1))
            if len(password_1) < 8:
                flash("password must be minimum 4 selections")
                return redirect(url_for('login'))
            else:
                password = password_1

        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        return redirect(url_for('profile'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

if __name__ == "__main__":
    app.run(debug=True)
