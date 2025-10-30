from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import InputRequired, Length, ValidationError, Optional, Email
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    student = db.relationship('Student', back_populates='user', uselist=False, cascade='all, delete-orphan')
    teacher = db.relationship('Teacher', back_populates='user', uselist=False, cascade='all, delete-orphan')

class Student(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    roll_number = db.Column(db.String(11), nullable=True)
    user = db.relationship('User', back_populates='student')


class Teacher(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    user = db.relationship('User', back_populates='teacher')


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(min=4, max=50)], render_kw={"placeholder": "email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    role = RadioField('Role', choices=[('student', 'Student'), ('teacher', 'Teacher')], default='student')
    roll_number = StringField(validators=[Optional()], render_kw={"placeholder": "Roll Number"})
    name = StringField(validators=[Optional(), Length(min=2, max=50)], render_kw={"placeholder": "Name"})
    contact_number = StringField(validators=[Optional(), Length(min=10, max=15)], render_kw={"placeholder": "Contact Number"})
    
    submit = SubmitField('Register')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email already exists. Please choose a different one.')
        
        
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')




@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        role = form.role.data or 'student'
        if role == 'student':
            if not form.name.data or not form.contact_number.data:
                flash('Student registration requires name and contact number.', 'error')
                return render_template('register.html', form=form)

        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        if role == 'student':
            student = Student(
                user_id=new_user.id,
                name=form.name.data,
                contact_number=form.contact_number.data,
                roll_number=form.roll_number.data,
            )
            db.session.add(student)
        else:
            teacher = Teacher(user_id=new_user.id)
            db.session.add(teacher)

        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == '__main__':
    # with app.app_context():
    #     db.create_all() 
    app.run(port=8000, debug=True)