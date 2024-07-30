from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import numpy as np
from tensorflow.keras.models import load_model
from PIL import Image
from pymongo import MongoClient
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'supersecretkey'

@app.route("/")
def index():
        return render_template("index.html")
        return redirect(url_for('index'))

# Koneksi ke MongoDB
client = MongoClient('mongodb://localhost:27017')
db = client.prediction_db

# Form untuk registrasi
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('user', 'User')], validators=[DataRequired()])
    submit = SubmitField('Register')

    # Validasi password
    def validate_password(self, password):
        # Memeriksa apakah password mengandung karakter khusus, huruf besar, dan angka
        if not re.search(r'[!@#$%^&*(),.?":{}|<>A-Z0-9]', password.data):
            raise ValidationError('Password harus mengandung setidaknya satu karakter khusus, huruf besar, dan angka.')

# Fungsi untuk meng-hash password
def hash_password(password):
    # Pastikan password dalam bentuk bytes
    password_bytes = password.encode('utf-8')
    # Generate salt dan hash password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password

# Fungsi untuk memverifikasi password
def check_password(plain_password, hashed_password):
    # Pastikan plain password dalam bentuk bytes
    plain_password_bytes = plain_password.encode('utf-8')
    # Verifikasi password
    return bcrypt.checkpw(plain_password_bytes, hashed_password)

def add_user(username, password, email, role):
    hashed_password = hash_password(password)  # Hash password and keep as bytes
    
    db.users.insert_one({
        "username": username,
        "password": hashed_password,
        "email" : email,
        "role": role
    })

def check_user(username, password):
    user = db.users.find_one({"username": username})
    if user:
        hashed_password = user['password']
        # Convert hashed_password to bytes if it's not already
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        
        if check_password(password, hashed_password):
            return user
    return None

def add_image(filename, predicted_label, file_path):
    db.images.insert_one({
        "filename": filename,
        "predicted_label": predicted_label,
        "file_path": file_path
    })

def get_all_images():
    return db.images.find()

# Daftar kelas label
labels = ['Bronchitis', 'Pneumonia', 'Tuberculosis']

def preprocess(img_path, input_size):
    nimg = img_path.convert('RGB').resize(input_size, resample=0)
    img_arr = (np.array(nimg)) / 255.0
    return img_arr

def reshape(imgs_arr):
    return np.stack(imgs_arr, axis=0)

@app.route("/predict", methods=['GET', 'POST'])
def get_output():
    if request.method == 'GET':
        return render_template("index.html")
    elif request.method == 'POST':
        if 'username' not in session:
            return redirect(url_for('login'))
        
        model = load_model('model2.h5', compile=False)
        img = request.files['photo']
        img_path = 'static/img/predict_img/' + img.filename
        img.save(img_path)
        im = Image.open(img_path)

        # Prediksi gambar
        input_size = (150, 150)
        X = preprocess(im, input_size)
        X = reshape([X])
        y = model.predict(X)
        hasil = labels[np.argmax(y)]

        # Simpan informasi gambar ke MongoDB
        add_image(img.filename, hasil, img_path)

        # Menampilkan hasil prediksi di halaman predict.html
        return render_template("predict.html", result=hasil, gambar=img_path, hasil=hasil)

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        add_user(form.username.data, form.password.data, form.role.data)
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("index.html")
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = check_user(username, password)
        
        if user:
            session['username'] = username
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index1'))
        else:
            flash("Login gagal. Username atau password salah.")
            return redirect(url_for('login'))

@app.route("/index1")
def index1():
    if 'username' in session:
        return render_template("index1.html")
    else:
        return redirect(url_for('login'))

@app.route("/admin_dashboard")
def admin_dashboard():
    if 'username' in session and session['role'] == 'admin':
        # Mendapatkan daftar pengguna dari database
        users = db.users.find()
        return render_template("admin_dashboard.html", users=users)
    else:
        return redirect(url_for('login'))
    
@app.route('/tambah_pengguna', methods=['GET', 'POST'])
def tambah_pengguna():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        
        # Validasi input (misalnya: konfirmasi password)
        if password != confirm_password:
            flash('Konfirmasi password tidak sesuai.', 'error')
            return redirect(url_for('tambah_pengguna'))
        
        # Cek apakah username sudah digunakan
        existing_user = db.users.find_one({'username': username})
        if existing_user:
            flash('Username sudah digunakan. Silakan gunakan username lain.', 'error')
            return redirect(url_for('tambah_pengguna'))
        
        # Tambahkan pengguna baru ke dalam database
        add_user(username, password, email, role)
        
        flash('Pengguna berhasil ditambahkan.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('tambah_pengguna.html')

@app.route('/hapus_pengguna/<username>', methods=['DELETE'])
def hapus_pengguna(username):
    result = db.users.delete_one({'username': username})
    if result.deleted_count == 1:
        return '', 204
    else:
        return '', 404

@app.route("/logout")
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route("/get_users_json")
def get_users_json():
    if 'username' in session and session['role'] == 'admin':
        users = list(db.users.find({}, {'_id': 0}))  # Menghapus _id dari hasil query MongoDB
        return jsonify(users)
    else:
        return jsonify({"error": "Unauthorized"})

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)
