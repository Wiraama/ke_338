from flask import *
from flask_sqlalchemy import SQLAlchemy
import os, base64
from send_mail import send_email
from functools import wraps


app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ke_338.db' # database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # for better perfomance
db = SQLAlchemy(app)


# user data
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    ben_number = db.Column(db.Integer, nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    f_name = db.Column(db.String(50), nullable=False)
    s_name = db.Column(db.String(50), nullable=False)
    d_pic = db.Column(db.LargeBinary)
    tel = db.Column(db.String(12))


    def __repr__(self):
        return f'<User: {self.ben_number}>'

@app.template_filter('b64encode')
def b64encode_filter(data):
    return base64.b64encode(data).decode('utf-8')
    
    
# login part
@app.route('/login', methods=['GET', 'POST'])
def login():
    feedback = None
    if request.method == 'POST':
        if 'signup' in request.form:
            ben_number = request.form.get('ben_number_signup')
            password = request.form.get('password_signup')
            c_pass = request.form.get('confirm_password_signup')
            if c_pass != password:
                feedback = 'password mismatch'
                return render_template('login.html', feedback=feedback)
            elif ben_number in User.query.all():
                feedback = 'Beneficiary number exist'
                return render_template('login.html', feedback=feedback)
            if len(password) < 8:
                feedback = 'Use Atleast 8 Characters for Password'
                return render_template('login.html', feedback=feedback)
            
            new_user = User(ben_number=ben_number, password=password)
            return redirect(url_for('register'))
            
        elif 'login' in request.form:
            ben_number = request.form['ben_number_login']
            password = request.form['password_login']
            user = User.query.filter_by(ben_number=ben_number).first()
            
            if user and user.password == password:
                session['ben_number'] = ben_number
                flash('Login Sucessful', 'success')
                return redirect(url_for('home')) 
            elif user and user['password'] == "":
                return render_template('login.html')
            flash('Login failed', 'danger')
            return render_template('login.html')

    return render_template('login.html')


#register
@app.route('/register', methods=['GET', 'POST'])
def register():
    d_pic_data = None
    if request.method == 'POST':
        ben_number = request.form.get('ben_number')
        password = request.form.get('password')
        f_name = request.form.get('f_name')
        s_name = request.form.get('s_name')
        d_pic = request.files.get('d_pic')
        tel = request.form.get('tel')
        if d_pic and d_pic.filename:
            d_pic_data = d_pic.read()

        new_user = User(
            ben_number=ben_number,
            password=password,
            f_name=f_name,
            s_name=s_name,
            d_pic=d_pic_data,
            tel=tel,
            )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html')

# handle forgotten password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        ben_number = request.form.get('ben_number')
        user = User.query.filter_by(ben_number=ben_number).first()
        if user:
            token = secrets.token_urlsafe(16)  # Generates a secure token
            # Store the token associated with the user (you might want to save it in the DB or an in-memory store)
            # user.reset_token = token  # Example of saving to the user's record
            # db.session.commit()  # Make sure to save the change in the database
            
            reset_link = url_for('reset_password', token=token, _external=True)
            send_email(email, "Password Reset", f"Click the link to reset your password: {reset_link}")
            flash('Reset link sent to your email', 'info')
        else:
            flash('Beneficiary number not found', 'danger')
        return redirect(url_for('forgot_password'))
        
    return render_template('forgot_password.html')

    
# reset password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('password missmatch', 'danger')
            return redirect(url_for('reset_password', token=token))
    
    user = verify_token(token)
    if user:
        user.password = password
        db.session.commit()
        flash('Save go to login', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')
    

# decorator ensure to start on login
def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'ben_number' not in session and request.endpoint != 'login' and request.endpoint != 'register':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
    
    
# admin part
def admin_login():
    # admin login
    passkey = '876543210'
    password = request.form.get('password')
    if password == passkey:
        return render_template('admin.html')
    return render_template('admin_log.html')
    

class Announce(db.Model):
    __tablename__ = 'data'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String, nullable=False)
    infomation = db.Column(db.String(500))

@app.route('/announce_data', methods=['GET', 'POST'])
def announce_data():
    if request.method == 'POST':
        category = request.form.get('category')
        infomation = request.form.get('infomation')

        new_data = Data(
            category=category,
            infomation=infomation,
            )
        db.session.add(new_data)
        db.session.commit()
        return redirect('announce_data')
    data = Announce.query.all()
    return render_template('announce.html', data=data)

# delete
@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    delete_data = Data.query.get(id)
    db.session.delete(delete_data)
    db.session.commit()
    return redirect(url_for('announce_data'))
    

# posting letter
class Letters(db.Model):
    __tablename__ = 'letters'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String, nullable=False)
    ben_number = db.Column(db.Integer, nullable=False)


@app.route('/post_letters', methods=['GET', 'POST'])
def post_letters():
    if request.method == 'POST':
        type = request.form.get('type')
        ben_number = request.form.get('ben_number')

        new_data = Letters(
            type=type,
            ben_number=ben_number,
            )
        db.session.add(new_data)
        db.session.commit()
        data = User.query.filter_by(ben_number=ben_number).first()
        if data:
            full_name = data.f_name + " " + data.s_name
        return redirect(url_for('post_letters'))
    else:
        full_name = ""
    letters = Letters.query.all()
    
    return render_template('post_letters.html', letters=letters, full_name=full_name)


# landing page
@app.route('/landing')
def landing():
    first_time = request.cookies.get('first_time')
    if first_time:
        return redirect(url_for('landing'))
    else:
        response = make_response(redirect(url_for('landing')))
        response.set_cookie('first_time', 'no', max_age=60*60*24*30*12)
        return response


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    return render_template('admin.html')
 

# home part
@app.route('/')
@require_login
def home():
    ben_number = session.get('ben_number')
    user = User.query.filter_by(ben_number=ben_number).first()
    data = Announce.query.all()
    
    if user:
        full_name = f"{user.f_name} {user.s_name}"
        
    return render_template('home.html', full_name=full_name, data=data)

# letter part
@app.route('/letter')
@require_login
def letter():
    return render_template('letters.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8000)
