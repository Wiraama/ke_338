from flask import *
from flask_sqlalchemy import SQLAlchemy
import os, base64
from send_mail import send_email
from functools import wraps
from datetime import datetime

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



######################## announce ##############################
class Announce(db.Model):
    __tablename__ = 'announce'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String, nullable=False)
    infomation = db.Column(db.String(500))

@app.route('/announce_data', methods=['GET', 'POST'])
def announce_data():
    if request.method == 'POST':
        category = request.form.get('category')
        infomation = request.form.get('infomation')

        new_data = Announce(
            category=category,
            infomation=infomation,
            )
        db.session.add(new_data)
        db.session.commit()
        return redirect(url_for('announce_data'))
    announce = Announce.query.all()
    return render_template('announce.html', announce=announce)

# delete
@app.route('/delete_announce/<int:id>', methods=['POST'])
def delete_announce(id):
    delete_data = Announce.query.get(id)
    db.session.delete(delete_data)
    db.session.commit()
    return redirect(url_for('announce_data'))
######################### end of announce ###########################

################################## Events #############################
class Events(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    infomation = db.Column(db.String(500))
    
@app.route('/events', methods=['GET', 'POST'])
def events():
    if request.method == 'POST':
        date_html = request.form.get('date')
        infomation = request.form.get('infomation')
        date = datetime.strptime(date_html, '%Y-%m-%d').date()

        new_data = Events(
            date=date,
            infomation=infomation,
            )
        db.session.add(new_data)
        db.session.commit()
        return redirect(url_for('events'))
    events = Events.query.all()
    return render_template('events.html', events=events)
    
# delete
@app.route('/delete_events/<int:id>', methods=['POST'])
def delete_events(id):
    delete_data = Events.query.get(id)
    db.session.delete(delete_data)
    db.session.commit()
    return redirect(url_for('events'))
################################ end Events  ###############################


# #####################################letter part############################
# posting letter
class Letters(db.Model):
    __tablename__ = 'letters'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String, nullable=False)
    ben_number = db.Column(db.Integer, nullable=False)
    
    
@app.route('/letter')
@require_login
def letter():
    letters = Letters.query.all()
    letters = sorted(letters, key=lambda letter: letter.ben_number)
    full_name = {}
    for letter in letters:
        user = User.query.filter_by(ben_number=letter.ben_number).first()
        if user:
            full_name[letter.ben_number] = f"{user.f_name} {user.s_name}"
        else:
            full_name[letter.ben_number] = ""
    return render_template('letters.html', letters=letters, full_name=full_name)

@app.route('/post_letters', methods=['GET', 'POST'])
def post_letters():
    if request.method == 'POST':
        type = request.form.get('type')
        ben_numbers = request.form.get('ben_number')
        
        ben_number_list = [num.strip() for num in ben_numbers.split(' ')]

        for ben_number in ben_number_list:
            new_data = Letters(
                type=type,
                ben_number=ben_number,
                )
            db.session.add(new_data)
        db.session.commit()
  
        return redirect(url_for('post_letters'))
    
    letters = Letters.query.all()
    letters = sorted(letters, key=lambda letter: letter.ben_number)
    full_name = {}
    for letter in letters:
        user = User.query.filter_by(ben_number=letter.ben_number).first()
        if user:
            full_name[letter.ben_number] = f"{user.f_name} {user.s_name}"
        else:
            full_name[letter.ben_number] = ""


    return render_template('post_letters.html', letters=letters, full_name=full_name)

@app.route('/delete_letters', methods=['POST'])
def delete_letters():
    delete_all = request.form.getlist('ben_numbers')
    
    if delete_all:
        for ben_number in delete_all:
            letter_del = Letters.query.filter_by(ben_number=ben_number).first()
            if letter_del:
                db.session.delete(letter_del)
    db.session.commit()
    return redirect(url_for('post_letters'))
##########################end of letters###########################


##############################Outdated############################
class Outdated(db.Model):
    __tablename__ = 'outdated'
    id = db.Column(db.Integer, primary_key=True)
    ben_number = db.Column(db.Integer, nullable=False)

@app.route('/outdated', methods=['GET', 'POST'])
def outdated():
    if request.method == 'POST':
        ben_numbers = request.form.get('ben_number')
        ben_num_list = [num.strip() for num in ben_numbers.split(' ')]
        
        for ben_number in ben_num_list:
            new_data = Outdated(
                ben_number=ben_number,
                )
            db.session.add(new_data)
        db.session.commit()
        return redirect(url_for('outdated'))
    outdated = Outdated.query.all()
    outdated = sorted(outdated, key=lambda leave: leave.ben_number)
    full_name = {}
    for ben_num in outdated:
        user = User.query.filter_by(ben_number=ben_num.ben_number).first()
        if user:
            full_name[ben_num.ben_number] = f"{user.f_name} {user.s_name}"

    return render_template('outdated.html', outdated=outdated, full_name=full_name)

# delete
@app.route('/delete_outdated/<int:id>', methods=['POST'])
def delete_outdated(id):
    delete_data = Outdated.query.get(id)
    db.session.delete(delete_data)
    db.session.commit()
    return redirect(url_for('outdated'))
##########################end of outdated###########################


###############################landing page####################
@app.route('/landing')
def landing():
    first_time = request.cookies.get('first_time')
    if first_time:
        return redirect(url_for('home'))
    else:
        response = make_response(redirect(url_for('landing')))
        response.set_cookie('first_time', 'no', max_age=60*60*24*30*12)
        return response
#################################end of landing page################################


###########################admin page ##############################
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    return render_template('admin.html')
##################end of admin page####################################

########################$$$$ home part##############################
@app.route('/')
@require_login
def home():
    ben_number = session.get('ben_number')
    user = User.query.filter_by(ben_number=ben_number).first()
    announce = Announce.query.all()
    events = Events.query.all()
    outdated = Outdated.query.all()
    outdated = sorted(outdated, key=lambda student: student.ben_number)

    full_names = {}
    for ben_num in outdated:
        user = User.query.filter_by(ben_number=ben_num.ben_number).first()
        if user:
            full_names[ben_num.ben_number] = f"{user.f_name} {user.s_name}"

    if user:
        full_name = f"{user.f_name} {user.s_name}"
        
    return render_template('home.html', events=events, full_name=full_name, announce=announce, outdated=outdated, full_names=full_names)
###########################end of home part #############################

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8000)
