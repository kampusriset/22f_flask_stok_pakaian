from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pakaian.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

# Model User untuk pendaftaran dan login
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Model Pakaian untuk data produk
class Pakaian(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(100), nullable=False)
    harga = db.Column(db.Float, nullable=False)
    stok = db.Column(db.Integer, nullable=False)

# Halaman Registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Periksa apakah username sudah digunakan
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username sudah terdaftar!', 'danger')
            return redirect(url_for('register'))

        # Enkripsi password sebelum disimpan
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user_baru = User(username=username, password=hashed_password)

        db.session.add(user_baru)
        db.session.commit()

        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Halaman Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash('Login gagal! Periksa kembali username dan password.', 'danger')

    is_logged_in = session.get('logged_in', False)
    return render_template('login.html', is_logged_in=is_logged_in)

# Logout
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# Halaman Utama
@app.route('/')
def index():
    return redirect(url_for('login'))

# Halaman Dashboard
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    pakaian = Pakaian.query.all()
    return render_template('index.html', pakaian=pakaian)

# Tambah Data Pakaian
@app.route('/tambah', methods=['GET', 'POST'])
def tambah():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        nama = request.form['nama']
        harga = request.form['harga']
        stok = request.form['stok']
        pakaian_baru = Pakaian(nama=nama, harga=float(harga), stok=int(stok))
        db.session.add(pakaian_baru)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('tambah.html')

# Edit Data Pakaian
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    pakaian = Pakaian.query.get(id)
    if request.method == 'POST':
        pakaian.nama = request.form['nama']
        pakaian.harga = float(request.form['harga'])
        pakaian.stok = int(request.form['stok'])
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('edit.html', pakaian=pakaian)

# Hapus Data Pakaian
@app.route('/hapus/<int:id>')
def hapus(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    pakaian = Pakaian.query.get(id)
    db.session.delete(pakaian)
    db.session.commit()
    return redirect(url_for('dashboard'))

# Ganti Password
@app.route('/ganti_password', methods=['GET', 'POST'])
def ganti_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        password_lama = request.form['password_lama']
        password_baru = request.form['password_baru']
        konfirmasi_password = request.form['konfirmasi_password']
        
        # Ambil data user yang sedang login
        user = User.query.filter_by(username=session['username']).first()
        
        # Cek password lama
        if not check_password_hash(user.password, password_lama):
            flash('Password lama tidak sesuai!', 'danger')
            return redirect(url_for('ganti_password'))
            
        # Cek konfirmasi password
        if password_baru != konfirmasi_password:
            flash('Konfirmasi password baru tidak sesuai!', 'danger')
            return redirect(url_for('ganti_password'))
            
        # Update password
        user.password = generate_password_hash(password_baru, method='pbkdf2:sha256')
        db.session.commit()
        
        flash('Password berhasil diubah!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('ganti_password.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
