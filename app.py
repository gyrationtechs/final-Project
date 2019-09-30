from datetime import datetime
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

#install flask security to authenticate admin users -- pip install flask_security


app = Flask(__name__)
app.config['SECRET_KEY'] = '927f9b175bfa8a197354f63daf1cfb38'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
Bootstrap(app)
login_manager = LoginManager(app)
#login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info'


class Student(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(12), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    profile = db.Column(db.String(20), nullable=False, default='profile.jpg')
    department = db.Column(db.String(60), nullable=False, default='Electrical Electronics Engineering')
    level = db.Column(db.Integer, default='100')
    posts = db.relationship('Post', backref='author', lazy=True)

    def __repr__(self):
        return f"Student('{self.first_name}', '{self.last_name}', '{self.username}', '{self.email}', '{self.department}', '{self.level}', {self.password}')"



@login_manager.user_loader
def load_user(student_id):
    return Student.query.get(int(student_id))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False) 

    def __repr__(self):
        return f"Student('{self.title}', '{self.date_posted}')"




class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))


admin = Admin(app, index_view=MyAdminIndexView())
admin.add_view(MyModelView(Student, db.session))
admin.add_view(MyModelView(Post, db.session))


class LoginForm(FlaskForm):
    username = StringField('Username / Mat No', validators=[InputRequired(), Length(min=12, max=12)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[InputRequired(), Length(max=120), Email(message = 'Invalid Email')])
    username = StringField('Username / Mat No', validators=[InputRequired(), Length(min=12, max=12)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        student = Student.query.filter_by(username=username.data).first()
        if student:
            raise ValidationError('Student already exists for that username. Please check your matric number correctly')

    def validate_email(self, email):
        student = Student.query.filter_by(email=email.data).first()
        if student:
            raise ValidationError('That email is choosen. Please choose a different one')



class UpdateAccountForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[InputRequired(), Length(max=120), Email(message = 'Invalid Email')])
    username = StringField('Username / Mat No', validators=[InputRequired(), Length(min=12, max=12)])
    department = StringField('Department', validators=[InputRequired(), Length(min=3, max=100)])
    level = StringField('Level', validators=[InputRequired(), Length(min=3, max=10)])
    submit = SubmitField('Register')


    def validate_username(self, username):
        student = Student.query.filter_by(username=username.data).first()
        if student:
            raise ValidationError('Student already exists for that username. Please check your matric number correctly')


    def validate_email(self, email):
        student = Student.query.filter_by(email=email.data).first()
        if student:
            raise ValidationError('That email is choosen. Please choose a different one')


@app.route('/')
@app.route('/home')
def home(): 
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        student = Student.query.filter_by(username=form.username.data).first()
        if student:
            if check_password_hash(student.password, form.password.data):
                login_user(student, remember=form.remember.data)
                next_page = request.args.get('next')
                flash(f'Login Successful for {form.username.data}!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        flash('Invalid Login Details. Please check username or password', 'danger')
        return redirect(url_for('login'))
        
    return render_template('login.html', title='Login', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_student = Student(first_name=form.first_name.data, last_name=form.last_name.data, username=form.username.data, 
                              email=form.email.data, password=hashed_password)
        db.session.add(new_student)
        db.session.commit()
        flash(f'Account Created for {form.username.data}!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Signup', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    profile = url_for('static', filename='images/' + current_user.profile)
    return render_template('dashboard.html', title='Dashboard', profile=profile)


@app.route('/dashboard/edit')
@login_required
def edit():
    profile = url_for('static', filename='images/' + current_user.profile)
    return render_template('edit.html', title='Dashboard', profile=profile)


@app.route('/about')
def about():
    return render_template('about.html', title='About')


@app.route('/contact')
def contact():
    return render_template('contact.html', title='Contact')


@app.route('/forum')
def forum():
    return render_template('forum.html', title='EEE Forum')


@app.route('/forget')
def forget():
    return render_template('forget.html', title='Forget Password')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)