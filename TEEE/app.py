#Install the required Python packages
# pip install flask
# pip install flask_sqlalchemy
# pip install sqlalchemy


from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# Database Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///travel_ease.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "travel_ease_secret"

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')

# Add these configurations:
app.config['SESSION_COOKIE_SECURE'] = True  # Use secure cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session expiration

db = SQLAlchemy(app)
mail = Mail(app)

# ------------ Models ------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expires = db.Column(db.DateTime)
    bookings = db.relationship('Booking', backref='user', lazy=True)

class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    packages = db.relationship('Package', backref='destination', lazy=True)

class Package(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    destination_id = db.Column(db.Integer, db.ForeignKey('destination.id'), nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # in days
    price_per_person = db.Column(db.Float, nullable=False)
    max_people = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    inclusions = db.Column(db.Text)  # What's included in the package
    exclusions = db.Column(db.Text)  # What's not included
    itinerary = db.Column(db.Text)  # Day-by-day plan
    bookings = db.relationship('Booking', backref='package', lazy=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    package_id = db.Column(db.Integer, db.ForeignKey('package.id'), nullable=False)
    booking_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    travel_date = db.Column(db.DateTime, nullable=False)
    number_of_people = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, confirmed, cancelled
    payment_status = db.Column(db.String(20), nullable=False, default='pending')  # pending, paid, refunded
    special_requests = db.Column(db.Text)

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    def is_valid(self):
        return not self.used and datetime.utcnow() < self.expires_at

# Create Database Tables
with app.app_context():
    db.create_all()

# ------------ Routes ------------

@app.route("/")
def home():
    featured_destinations = Destination.query.limit(4).all()
    popular_packages = Package.query.order_by(Package.price_per_person.desc()).limit(4).all()
    return render_template("home.html", 
                         featured_destinations=featured_destinations,
                         popular_packages=popular_packages)

# Authentication Routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        
        flash("Invalid email or password", "error")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "error")
            return redirect(url_for("register"))
        
        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("home"))

# Password Reset Routes
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            # First, invalidate any existing tokens
            PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({"used": True})
            
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=expires_at
            )
            db.session.add(reset_token)
            try:
                db.session.commit()
                
                # Send email
                msg = Message('Password Reset Request',
                            recipients=[user.email])
                msg.body = f'''To reset your password, use the following token:

{token}

If you did not make this request, please ignore this email.
The token will expire in 1 hour.'''
                mail.send(msg)
                
                flash("Reset token has been sent to your email.", "success")
                return redirect(url_for('enter_reset_token'))
            except Exception as e:
                db.session.rollback()
                flash("An error occurred. Please try again.", "error")
                print(f"Error: {str(e)}")  # For debugging
        
        flash("Email address not found.", "error")
    return render_template("auth/forgot_password.html")

@app.route("/enter-reset-token", methods=["GET", "POST"])
def enter_reset_token():
    if request.method == "POST":
        token = request.form.get("token")
        reset_token = PasswordResetToken.query.filter_by(
            token=token,
            used=False
        ).first()
        
        if reset_token and reset_token.is_valid():
            return redirect(url_for('reset_password', token=token))
        
        flash("Invalid or expired token.", "error")
    return render_template("auth/enter_reset_token.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(
        token=token,
        used=False
    ).first()
    
    if not reset_token or not reset_token.is_valid():
        flash("Invalid or expired token.", "error")
        return redirect(url_for('forgot_password'))
    
    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('reset_password', token=token))
        
        user = User.query.get(reset_token.user_id)
        user.password = generate_password_hash(password)
        reset_token.used = True
        try:
            db.session.commit()
            flash("Your password has been reset successfully.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred. Please try again.", "error")
            print(f"Error: {str(e)}")  # For debugging
    
    return render_template("auth/reset_password.html")

# Package and Destination Routes
@app.route("/packages")
def packages():
    packages = Package.query.all()
    return render_template("packages.html", packages=packages)

@app.route("/package/<int:package_id>")
def package_details(package_id):
    package = Package.query.get_or_404(package_id)
    return render_template("package_details.html", package=package)

@app.route("/destinations")
def destinations():
    destinations = Destination.query.all()
    return render_template("destinations.html", destinations=destinations)

@app.route("/destination/<int:destination_id>")
def destination_details(destination_id):
    destination = Destination.query.get_or_404(destination_id)
    packages = Package.query.filter_by(destination_id=destination_id).all()
    return render_template("destination_details.html", 
                         destination=destination,
                         packages=packages)

# Booking Routes
@app.route("/book-package/<int:package_id>", methods=["GET", "POST"])
def book_package(package_id):
    if 'user_id' not in session:
        flash("Please login to book a package.", "error")
        return redirect(url_for("login"))
    
    package = Package.query.get_or_404(package_id)
    
    if request.method == "POST":
        travel_date = datetime.strptime(request.form.get("travel_date"), "%Y-%m-%d")
        number_of_people = int(request.form.get("number_of_people"))
        special_requests = request.form.get("special_requests")
        
        if number_of_people > package.max_people:
            flash(f"Maximum {package.max_people} people allowed per booking.", "error")
            return redirect(url_for("book_package", package_id=package_id))
        
        total_price = package.price_per_person * number_of_people
        
        new_booking = Booking(
            user_id=session['user_id'],
            package_id=package_id,
            travel_date=travel_date,
            number_of_people=number_of_people,
            total_price=total_price,
            special_requests=special_requests
        )
        
        db.session.add(new_booking)
        db.session.commit()
        
        flash("Booking successful! Please complete the payment.", "success")
        return redirect(url_for("my_bookings"))
    
    return render_template("book_package.html", package=package)

@app.route("/my-bookings")
def my_bookings():
    if 'user_id' not in session:
        flash("Please login to view your bookings.", "error")
        return redirect(url_for("login"))
    
    user_id = session['user_id']
    bookings = Booking.query.filter_by(user_id=user_id)\
        .order_by(Booking.travel_date.desc()).all()
    return render_template("bookings/my_bookings.html", 
                         bookings=bookings, 
                         now=datetime.utcnow())

@app.route("/cancel-booking/<int:booking_id>", methods=["POST"])
def cancel_booking(booking_id):
    if 'user_id' not in session:
        flash("Please login to cancel bookings.", "error")
        return redirect(url_for("login"))
    
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != session['user_id']:
        flash("Unauthorized access.", "error")
        return redirect(url_for("my_bookings"))
    
    if booking.status == 'confirmed':
        booking.status = 'cancelled'
        db.session.commit()
        flash("Booking has been cancelled successfully.", "success")
    else:
        flash("Cannot cancel this booking.", "error")
    
    return redirect(url_for("my_bookings"))

# Add this function:
def is_password_strong(password):
    return len(password) >= 8 and any(char.isdigit() for char in password) and any(char.isalpha() for char in password)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)