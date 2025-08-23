from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session,send_file,abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
from threading import Thread
import jwt
from werkzeug.utils import secure_filename
import os
from flask_mail import Mail, Message
import uuid
import secrets
import hashlib
from datetime import datetime, timedelta
from waitress import serve
from datetime import datetime, timezone
import pytz
from datetime import timedelta
from flask import session  # Make sure this is imported
from datetime import timedelta

app = Flask(__name__)
app.config.update(
    SECRET_KEY='your-secret-key-here',
    
    # PostgreSQL Database Configuration
    SQLALCHEMY_DATABASE_URI='sqlite:///edutrade.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,  # Recommended to disable
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_pre_ping': True,  # Helps with connection drops
        'pool_recycle': 300,    # Recycle connections every 5 minutes
    },
    
    # File Upload Configuration
    UPLOAD_FOLDER=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads'),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    
    # Email Configuration
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='stud.studentsmart@gmail.com',
    MAIL_PASSWORD='jygr uhcl odmk flve',
    MAIL_DEFAULT_SENDER=('StudentsMart', 'stud.studentsmart@gmail.com'),
    
    # ADD THESE SESSION CONFIGURATIONS:
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),  # Sessions last 7 days
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
def check_mail_configuration():
    required_configs = [
        'MAIL_SERVER',
        'MAIL_PORT',
        'MAIL_USERNAME',
        'MAIL_PASSWORD',
        'MAIL_USE_TLS'
    ]

    missing_configs = [config for config in required_configs
                      if not app.config.get(config)]

    if missing_configs:
        print("WARNING: Missing email configurations:", missing_configs)
        return False
    return True
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'rtf', 'ppt', 'pptx', 'xls', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
IST = pytz.timezone('Asia/Kolkata')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    full_name = db.Column(db.String(100))
    department = db.Column(db.String(100))
    year = db.Column(db.Integer)
    roll_number = db.Column(db.String(50), unique=True, nullable=True)
    profile_picture = db.Column(db.String(200))
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(255), nullable=True)
    reset_token = db.Column(db.String(255))
    reset_token_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    college = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    unread_notifications = db.Column(db.Integer, default=0)
    
    # Relationships - keep EXACTLY as your original code
    listings = db.relationship('Listing', backref='seller', lazy=True)
    notifications = db.relationship('Notification', back_populates='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    rent_price = db.Column(db.Float)
    category = db.Column(db.String(50), nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    is_for_rent = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    
    # ONLY CHANGE: Added CASCADE DELETE to foreign key
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    
    
    # New fields
    product_type = db.Column(db.String(50))
    branch = db.Column(db.String(50))
    study_year = db.Column(db.String(20))
    working_condition = db.Column(db.String(50))
    warranty_status = db.Column(db.String(50))
    subject = db.Column(db.String(100))
    faculty_name = db.Column(db.String(100))
    is_fake_warning = db.Column(db.Boolean, default=False)
    is_softcopy = db.Column(db.Boolean, default=False)
    file_url = db.Column(db.String(200))


class MessageThread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # SET NULL: When user is deleted, keep messages but set sender/receiver to NULL
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="SET NULL"), nullable=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="SET NULL"), nullable=True)
    
    # CASCADE DELETE: When listing is deleted, delete all related messages
    listing_id = db.Column(db.Integer, db.ForeignKey('listing.id', ondelete="CASCADE"), nullable=True)
    
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    # Relationships - EXACTLY as your original
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    listing = db.relationship('Listing', backref='messages')
    
    # Self-referencing for replies
    parent_message_id = db.Column(db.Integer, db.ForeignKey('message_thread.id', ondelete="CASCADE"), nullable=True)
    replies = db.relationship('MessageThread', backref=db.backref('parent_message', remote_side=[id]))


class Wishlist(db.Model):
    __tablename__ = 'wishlist'
    id = db.Column(db.Integer, primary_key=True)
    
    # CASCADE DELETE: When user is deleted, delete their wishlist items
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    
    # CASCADE DELETE: When listing is deleted, remove from wishlists  
    listing_id = db.Column(db.Integer, db.ForeignKey('listing.id', ondelete="CASCADE"), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships - EXACTLY as your original
    user = db.relationship('User', backref='wishlist_items')
    listing = db.relationship('Listing', backref='wishlist_entries')


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # CASCADE DELETE: When user is deleted, delete their reports
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    
    # CASCADE DELETE: When listing is deleted, delete reports about it
    reported_listing_id = db.Column(db.Integer, db.ForeignKey('listing.id', ondelete="CASCADE"), nullable=True)
    
    # CASCADE DELETE: When message is deleted, delete reports about it
    message_thread_id = db.Column(db.Integer, db.ForeignKey('message_thread.id', ondelete="CASCADE"), nullable=True)
    
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200))
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships - EXACTLY as your original
    reporter = db.relationship('User', backref='reports_made')
    reported_listing = db.relationship('Listing', backref='reports')
    message_thread = db.relationship('MessageThread', backref='reports')


class SoldItem(db.Model):
    __tablename__ = 'sold_items'
    id = db.Column(db.Integer, primary_key=True)
    
    # CASCADE DELETE: When listing is deleted, delete sold record
    listing_id = db.Column(db.Integer, db.ForeignKey('listing.id', ondelete="CASCADE"), nullable=True)
    
    # CASCADE DELETE: When seller is deleted, delete their sold items
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    
    buyer_name = db.Column(db.String(100), nullable=False)
    buyer_email = db.Column(db.String(255), nullable=False)
    confirmation_token = db.Column(db.String(255), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending')
    sold_at = db.Column(db.DateTime, default=datetime.utcnow)
    confirmed_at = db.Column(db.DateTime)
    
    # Relationships - EXACTLY as your original
    listing = db.relationship('Listing', backref='sold_record')
    seller = db.relationship('User', backref='sold_items')


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    
    # CASCADE DELETE: When user is deleted, delete their notifications
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    
    type = db.Column(db.String(50), default='general')
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text)
    
    # CASCADE DELETE: When listing is deleted, delete related notifications
    listing_id = db.Column(db.Integer, db.ForeignKey('listing.id', ondelete="CASCADE"), nullable=True)
    
    buyer_email = db.Column(db.String(255))
    buyer_name = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship - EXACTLY as your original
    user = db.relationship('User', back_populates='notifications')
    listing = db.relationship('Listing', backref='notifications')


ALLOWED_DOMAINS = ['ac.in', 'edu', 'org', 'in', 'org.in', 'ac.edu', 'ac.co.in']
def send_buyer_confirmation_email(buyer_email, buyer_name, listing, token, seller_name):
    try:
        confirm_url = url_for('confirm_purchase', token=token, action='confirm', _external=True)
        deny_url = url_for('confirm_purchase', token=token, action='deny', _external=True)
        
        msg = Message(
            subject=f'Confirm your purchase - {listing.title}',
            recipients=[buyer_email],
            html=f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>Purchase Confirmation Required</h2>
                <p>Hello {buyer_name},</p>
                <p>{seller_name} from {listing.seller.college} has marked the following item as sold to you:</p>
                
                <div style="border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px;">
                    <h3>{listing.title}</h3>
                    <p><strong>Price:</strong> ₹{listing.price}</p>
                    <p><strong>Category:</strong> {listing.category}</p>
                </div>
                
                <p>Please confirm whether you have purchased this item:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{confirm_url}" style="background-color: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 0 10px; display: inline-block;">
                        Yes, I bought this
                    </a>
                    <a href="{deny_url}" style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 0 10px; display: inline-block;">
                        No, I didn't buy this
                    </a>
                </div>
                
                <p><em>This is an automated email from StudentsMart. Please do not reply.</em></p>
            </div>
            """
        )
        mail.send(msg)
    except Exception as e:
        print(f"Email sending failed: {e}")

def send_admin_sale_notification(sold_item, listing):
    try:
        admin_email = "contactstudentsmart@gmail.com"
        msg = Message(
            subject=f'Sale Confirmed - {listing.title if listing else "Listing"}',
            recipients=[admin_email],
            html=f"""
            <h3>Sale Confirmation Report</h3>
            <p><strong>Listing:</strong> {listing.title if listing else 'N/A'}</p>
            <p><strong>Seller:</strong> {sold_item.seller.full_name} ({sold_item.seller.college})</p>
            <p><strong>Buyer:</strong> {sold_item.buyer_name} ({sold_item.buyer_email})</p>
            <p><strong>Sale Date:</strong> {sold_item.confirmed_at}</p>
            <p><strong>Price:</strong> ₹{listing.price if listing else 'N/A'}</p>
            """
        )
        mail.send(msg)
    except Exception as e:
        print(f"Admin notification failed: {e}")

def send_verification_email(email, token):
    try:
        if not check_mail_configuration():
            print("Email configuration is incomplete")
            return False

        msg = Message('Verify Your StudentsMart Account',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        verification_url = url_for('verify_email', token=token, _external=True)
        msg.body = f'Click to verify your account: {verification_url}'
        
        try:
            mail.send(msg)
            print(f"Verification email sent successfully to {email}")
            return True
        except Exception as e:
            print(f"Failed to send verification email: {str(e)}")
            if "Username and Password not accepted" in str(e):
                print("Please check your Gmail credentials and make sure:")
                print("1. 2-Step Verification is enabled on your Gmail account")
                print("2. You're using an App Password instead of your regular password")
                print("3. The App Password is correctly copied without spaces")
            return False
    except Exception as e:
        print(f"Error in send_verification_email: {str(e)}")
        return False

def save_image(image):
    if not image:
        return None
    filename = secure_filename(image.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    image.save(image_path)
    return f"uploads/{unique_filename}"
@app.route('/')
def index():
    return send_file('index.html')
@app.route('/mark_sold/<int:listing_id>', methods=['POST'])
@login_required
def mark_sold(listing_id):
    try:
        listing = Listing.query.filter_by(id=listing_id, seller_id=current_user.id).first()
        if not listing:
            return jsonify({'success': False, 'message': 'Listing not found'})
        
        buyer_name = request.form.get('buyer_name', '').strip()
        buyer_email = request.form.get('buyer_email', '').strip()
        
        if not buyer_name or not buyer_email:
            return jsonify({'success': False, 'message': 'Please provide buyer name and email'})
        
        # Generate confirmation token
        confirmation_token = secrets.token_urlsafe(32)
        
        # Create sold item record
        sold_item = SoldItem(
            listing_id=listing_id,
            seller_id=current_user.id,
            buyer_name=buyer_name,
            buyer_email=buyer_email,
            confirmation_token=confirmation_token
        )
        db.session.add(sold_item)
        
        # Create notification
        notification = Notification(
            user_id=current_user.id,
            type='sale_confirmation',
            title=f'Purchase confirmation required',
            message=f'Please confirm your purchase of "{listing.title}"',
            listing_id=listing_id,
            buyer_email=buyer_email,
            buyer_name=buyer_name
        )
        db.session.add(notification)
        db.session.commit()
        
        # Send confirmation email to buyer
        send_buyer_confirmation_email(buyer_email, buyer_name, listing, confirmation_token, current_user.full_name)
        
        return jsonify({'success': True, 'message': 'Confirmation email sent to buyer'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/confirm_purchase/<token>')
def confirm_purchase(token):
    try:
        action = request.args.get('action', 'confirm')
        sold_item = SoldItem.query.filter_by(confirmation_token=token).first()
        
        if not sold_item:
            flash('Invalid or expired confirmation link', 'error')
            return redirect(url_for('index'))
        
        if action == 'confirm':
            # Get listing and save title BEFORE deleting
            listing = sold_item.listing
            if not listing:
                flash('Listing not found', 'error')
                return redirect(url_for('index'))
                
            # Store listing data before deletion
            listing_title = listing.title
            listing_data = {
                'title': listing.title,
                'price': listing.price,
                'description': listing.description
            }
            
            # FIRST: Clean up ALL related records before deleting listing
            listing_id = listing.id
            
            # Delete related notifications
            Notification.query.filter_by(listing_id=listing_id).delete()
            
            # Delete related wishlist entries
            from sqlalchemy import text
            db.session.execute(text("DELETE FROM wishlist WHERE listing_id = :listing_id"), 
                             {"listing_id": listing_id})
            
            # Delete any other related records if they exist
            # Add more cleanup here if you have other tables referencing listing
            
            # Update sold item status
            sold_item.status = 'confirmed'
            sold_item.confirmed_at = datetime.utcnow()
            
            # Now delete the listing (all references are cleaned up)
            db.session.delete(listing)
            
            # Create notification WITHOUT listing_id (since listing is deleted)
            notification = Notification(
                user_id=sold_item.seller_id,
                type='purchase_confirmed',
                title='Purchase Confirmed',
                message=f'Your item "{listing_title}" has been confirmed as sold to {sold_item.buyer_name}',
                listing_id=None,  # Set to None since listing is deleted
                buyer_email=sold_item.buyer_email,
                buyer_name=sold_item.buyer_name,
                status='confirmed'
            )
            db.session.add(notification)
            
            # Commit ALL changes together
            db.session.commit()
            
            return render_template('confirmation_success.html', 
                                 listing=listing_data,
                                 buyer_name=sold_item.buyer_name)
        
        elif action == 'deny':
            sold_item.status = 'denied'
            db.session.commit()
            return render_template('confirmation_denied.html')
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in confirm_purchase: {str(e)}")
        return render_template('confirmation_error.html', 
                             error_message="An error occurred while processing your request.")

    print(f"Token received: {token}")
    print(f"SoldItem found: {sold_item}")
    print(f"Action: {action}")

@app.route('/notifications')
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).all()
    
    # Mark as read
    current_user.unread_notifications = 0
    db.session.commit()
    
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/api/notification_count')
@login_required
def notification_count():
    count = Notification.query.filter_by(user_id=current_user.id, status='pending').count()
    return jsonify({'count': count})
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({
                'error': 'Email is required',
                'error_code': 'MISSING_EMAIL'
            }), 400
        
        # Find the user
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        
        if not user:
            # Don't reveal that the email doesn't exist for security
            return jsonify({
                'message': 'If this email exists in our system, we\'ve sent a verification link.',
                'success': True
            }), 200
        
        if user.is_verified:
            return jsonify({
                'error': 'This email is already verified',
                'error_code': 'ALREADY_VERIFIED'
            }), 400
        
        # Generate new verification token
        verification_token = secrets.token_urlsafe(32)
        user.verification_token = verification_token
        user.verification_token_expires = datetime.utcnow() + timedelta(hours=24)
        
        db.session.commit()
        
        # Send verification email
        verification_link = url_for('verify_email', token=verification_token, _external=True)
        
        # Your email sending logic here
        send_verification_email(user.email, user.full_name, verification_link)
        
        return jsonify({
            'message': 'Verification email sent successfully',
            'success': True
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'error': 'Failed to send verification email',
            'error_code': 'SERVER_ERROR'
        }), 500


@app.route('/test-email')
def test_email():
    try:
        msg = Message('Test Email',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[app.config['MAIL_USERNAME']])
        msg.body = 'This is a test email'
        mail.send(msg)
        return jsonify({'message': 'Test email sent successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Authentication Routes
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.form
        email = data.get('email', '').strip().lower()
        roll_number = data.get('roll_number', '').strip()  # Get roll number
        
        # Check if roll number is provided and unique
        if roll_number:
            existing_roll = User.query.filter_by(roll_number=roll_number).first()
            if existing_roll:
                return jsonify({
                    'error': 'This roll number is already registered. Please use a different one or leave it blank.'
                }), 400

        # Validate email format
        if '@' not in email:
            return jsonify({'error': 'Invalid email format'}), 400

        # Split domain parts
        domain = email.split('@')[-1]
        domain_parts = domain.split('.')

        # Check against allowed domains
        ALLOWED_DOMAINS = ['ac.in', 'edu', 'org', 'in','org.in', 'ac.edu','ac.co.in','com']
        valid_domain = any(
            '.'.join(domain_parts[-len(d.split('.')):]) == d
            for d in ALLOWED_DOMAINS
        )

        if not valid_domain:
            return jsonify({
                'error': 'Only institutional emails allowed. Valid domains: ' + ', '.join(ALLOWED_DOMAINS)
            }), 400

        # Check existing user
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400

        # Create verification token
        verification_token = str(uuid.uuid4())

        # Create new user
        user = User(
            email=email,
            full_name=data['full_name'],
            department=data['department'],
            year=int(data['year']),
            college=data['college'],
            is_verified=False,
            verification_token=verification_token,
            roll_number=roll_number if roll_number else None
        )
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        # Send verification email
        try:
            msg = Message('Verify Your Studentsmart Account',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
            verification_url = url_for('verify_email', token=verification_token, _external=True)
            
            msg.body = f'''Hi {user.full_name},

        Thank you for registering with Studentsmart! We're excited to have you join our community.

        To complete your registration Process, please click the verification link below:
        {verification_url}

        If you didn't create this account, please ignore this email and no further action is required.

        Please note: This is an automated email, so please do not reply to this message.

        We're looking forward to having a great time together on Studentsmart!

        Best regards,
        Team Studentsmart'''
            mail.send(msg)
        except Exception as e:
            db.session.rollback()
            print(f"Failed to send verification email: {str(e)}")
            return jsonify({'error': 'Failed to send verification email'}), 500

        return jsonify({
            'message': 'Registration successful! Please check your email to verify your account.',
            'user_id': user.id
        })

    except KeyError as e:
        return jsonify({'error': f'Missing required field: {str(e)}'}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.form
       
        if not all(k in data for k in ['email', 'password']):
            return jsonify({
                'error': 'Missing email or password',
                'error_code': 'MISSING_FIELDS'
            }), 400
            
        user = db.session.execute(db.select(User).filter_by(email=data['email'])).scalar_one_or_none()
        
        if not user or not user.check_password(data['password']):
            return jsonify({
                'error': 'Invalid email or password',
                'error_code': 'INVALID_CREDENTIALS'
            }), 401
            
        if not user.is_verified:
            return jsonify({
                'error': 'Dear Student! could you please verify the link that sent to your mail',
                'error_code': 'EMAIL_NOT_VERIFIED',
                'email': user.email
            }), 401
            
        # UPDATED: Add remember=True and make session permanent
        login_user(user, remember=True)  # This will remember the user
        session.permanent = True         # Make the session permanent
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'department': user.department,
                'year': user.year,
                'is_admin': user.is_admin,
                'roll_number': user.roll_number
            }
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'error_code': 'SERVER_ERROR'
        }), 500
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        email = request.json.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if not user:
            return jsonify({'error': 'Email not found'}), 404

        # Generate reset token
        reset_token = str(uuid.uuid4())
        user.reset_token = reset_token
        user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()

        # Send reset email
        send_reset_email(email, reset_token)

        return jsonify({'message': 'Password reset instructions sent to your email'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.json
        if not all(k in data for k in ['token', 'new_password']):
            return jsonify({'error': 'Missing required fields'}), 400

        user = db.session.execute(db.select(User).filter_by(reset_token=data['token'])).scalar_one_or_none()
        if not user or user.reset_token_expiry < datetime.utcnow():
            return jsonify({'error': 'Invalid or expired reset token'}), 400

        user.set_password(data['new_password'])
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()

        return jsonify({'message': 'Password reset successful'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        user = db.session.execute(db.select(User).filter_by(verification_token=token)).scalar_one_or_none()
        if not user:
            error_html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Verify Your StudenTsmart Account</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
                <style>
                    :root {
                        --primary-color: #2563eb;
                        --secondary-color: #3b82f6;
                        --accent-color: #60a5fa;
                        --success-color: #22c55e;
                        --error-color: #ef4444;
                        --text-dark: #1f2937;
                        --text-light: #6b7280;
                        --background-light: #f3f4f6;
                    }
                    
                    body {
                        font-family: 'Inter', sans-serif;
                        background-color: var(--background-light);
                        color: var(--text-dark);
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    
                    .error-container {
                        text-align: center;
                        padding: 2rem;
                        background-color: white;
                        border-radius: 1rem;
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        width: 90%;
                        max-width: 500px;
                    }
                    
                    h1 {
                        color: var(--error-color);
                        margin-bottom: 1rem;
                    }
                    
                    p {
                        color: var(--text-light);
                        margin-bottom: 1.5rem;
                    }
                    
                    .btn-primary {
                        display: inline-block;
                        background-color: var(--primary-color);
                        color: white;
                        text-decoration: none;
                        border-radius: 0.5rem;
                        padding: 0.75rem 1.5rem;
                        font-weight: 600;
                        transition: background-color 0.2s;
                    }
                    
                    .btn-primary:hover {
                        background-color: var(--secondary-color);
                    }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <h1>Invalid Verification Link</h1>
                    <p>The verification link you clicked is invalid or has expired.</p>
                    <a href="/" class="btn-primary">Get to the website</a>
                </div>
            </body>
            </html>
            """
            return error_html, 400
        
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        
        # Return HTML success page with custom styling
        success_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verify Your StudenTsmart Account</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
            <style>
                :root {
                    --primary-color: #2563eb;
                    --secondary-color: #3b82f6;
                    --accent-color: #60a5fa;
                    --success-color: #22c55e;
                    --error-color: #ef4444;
                    --text-dark: #1f2937;
                    --text-light: #6b7280;
                    --background-light: #f3f4f6;
                }
                
                body {
                    font-family: 'Inter', sans-serif;
                    background-color: var(--background-light);
                    color: var(--text-dark);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                
                .success-container {
                    text-align: center;
                    padding: 2rem;
                    background-color: white;
                    border-radius: 1rem;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    width: 90%;
                    max-width: 500px;
                }
                
                h1 {
                    color: var(--success-color);
                    margin-bottom: 1rem;
                }
                
                p {
                    color: var(--text-light);
                    margin-bottom: 1.5rem;
                }
                
                .check-icon {
                    font-size: 60px;
                    color: var(--success-color);
                    margin-bottom: 1rem;
                }
                
                .btn-primary {
                    display: inline-block;
                    background-color: var(--primary-color);
                    color: white;
                    text-decoration: none;
                    border-radius: 0.5rem;
                    padding: 0.75rem 1.5rem;
                    font-weight: 600;
                    transition: background-color 0.2s;
                }
                
                .btn-primary:hover {
                    background-color: var(--secondary-color);
                }
            </style>
        </head>
        <body>
            <div class="success-container">
                <div class="check-icon">✓</div>
                <h1>Verify Your StudentsMart Account</h1>
                <p>Your email has been verified successfully! You can now access the StudenTsmart website.</p>
                <a href="/" class="btn-primary">Get to the website</a>
            </div>
        </body>
        </html>
        """
        return success_html
        
    except Exception as e:
        db.session.rollback()
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verification Error</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
            <style>
                :root {{
                    --primary-color: #2563eb;
                    --secondary-color: #3b82f6;
                    --accent-color: #60a5fa;
                    --success-color: #22c55e;
                    --error-color: #ef4444;
                    --text-dark: #1f2937;
                    --text-light: #6b7280;
                    --background-light: #f3f4f6;
                }}
                
                body {{
                    font-family: 'Inter', sans-serif;
                    background-color: var(--background-light);
                    color: var(--text-dark);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                
                .error-container {{
                    text-align: center;
                    padding: 2rem;
                    background-color: white;
                    border-radius: 1rem;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    width: 90%;
                    max-width: 500px;
                }}
                
                h1 {{
                    color: var(--error-color);
                    margin-bottom: 1rem;
                }}
                
                p {{
                    color: var(--text-light);
                    margin-bottom: 1.5rem;
                }}
                
                .btn-primary {{
                    display: inline-block;
                    background-color: var(--primary-color);
                    color: white;
                    text-decoration: none;
                    border-radius: 0.5rem;
                    padding: 0.75rem 1.5rem;
                    font-weight: 600;
                    transition: background-color 0.2s;
                }}
                
                .btn-primary:hover {{
                    background-color: var(--secondary-color);
                }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>Verification Error</h1>
                <p>An error occurred during verification. Please try again later.</p>
                <a href="/" class="btn-primary">Get to the website</a>
            </div>
        </body>
        </html>
        """
        return error_html, 500
# Listing Routes
@app.route('/create-listing', methods=['POST'])
@login_required
def create_listing():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image provided'}), 400

        image = request.files['image']
        if image.filename == '':
            return jsonify({'error': 'No image selected'}), 400

        # Save the image and get its path
        image_url = save_image(image)
        if not image_url:
            return jsonify({'error': 'Failed to save image'}), 500

        # Check if listing is for rent
        is_for_rent = request.form.get('is_for_rent') == 'true'

        # Set price and rent_price based on listing type
        price = 0
        rent_price = 0

        if is_for_rent:
            rent_price = float(request.form.get('rent_price', 0))
            # Optional: Store rental tenure in description or as a separate field
            rent_tenure = request.form.get('rent_tenure', '0')
        else:
            price = float(request.form.get('price', 0))
        
        is_softcopy = request.form.get('copy_type') == 'soft'
        file = request.files.get('document') if is_softcopy else None

        # Handle file upload
        if is_softcopy and file:
            if not allowed_file(file.filename):
                return jsonify({'error': 'Invalid file type. Only PDF and Word documents allowed'}), 400

            try:
                # Check if we can locate working files to understand the correct path
                working_files_check = []
                test_filenames = [
                    "2881bee4-a0ee-4efe-ae76-4dd654b79429_NLP_Exam_Preparation_Topics.pdf",
                    "603f8fa0-0fa4-4295-a383-81dd385778e2_N_L_RAM_CHARAN_TEJA.pdf"
                ]
                
                for test_file in test_filenames:
                    possible_locations = [
                        os.path.join(app.root_path, 'static', 'uploads', test_file),
                        os.path.join(os.getcwd(), 'static', 'uploads', test_file)
                    ]
                    
                    for location in possible_locations:
                        if os.path.exists(location):
                            working_files_check.append({
                                "file": test_file,
                                "found_at": location,
                                "exists": True
                            })
                            
                print(f"Working files check: {working_files_check}")
                
                # Ensure upload directory exists
                if working_files_check:
                    # Use the location where working files were found
                    uploads_dir = os.path.dirname(working_files_check[0]["found_at"])
                    print(f"Using uploads directory where working files were found: {uploads_dir}")
                else:
                    # Default location
                    uploads_dir = os.path.join(app.root_path, 'static', 'uploads')
                    print(f"No working files found, using default uploads directory: {uploads_dir}")
                
                os.makedirs(uploads_dir, exist_ok=True)

                # Generate a unique filename to prevent collisions
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                file_path = os.path.join(uploads_dir, filename)
                file.save(file_path)
                
                # Store only the filename without any path prefix
                file_url = filename
                
                print(f"Softcopy file saved at: {file_path}")
                print(f"Stored file_url as: {file_url}")
                print(f"File exists after save: {os.path.exists(file_path)}")
            except Exception as e:
                print(f"Error saving file: {str(e)}")
                return jsonify({'error': f'Failed to save file: {str(e)}'}), 500
        else:
            file_url = None
        # Create listing
        listing = Listing(
            title=request.form['title'],
            description=request.form['description'],
            price=price,
            rent_price=rent_price,
            category=request.form['category'],
            condition=request.form.get('working_condition', 'Not specified'),
            image_url=image_url,
            seller_id=current_user.id,
            product_type=request.form.get('product_type'),
            branch=request.form.get('branch'),
            study_year=request.form.get('study_year'),
            working_condition=request.form.get('working_condition'),
            warranty_status=request.form.get('warranty_status'),
            subject=request.form.get('subject'),
            faculty_name=request.form.get('faculty_name'),
            is_softcopy=is_softcopy,
            file_url=file_url,
            is_fake_warning=bool(request.form.get('is_fake_warning', False)),
            is_for_rent=is_for_rent
        )

        db.session.add(listing)
        db.session.commit()

        return jsonify({
            'message': 'Listing created successfully',
            'listing': {
                'id': listing.id,
                'title': listing.title,
                'description': listing.description,
                'price': listing.price,
                'rent_price': listing.rent_price,
                'category': listing.category,
                'condition': listing.condition,
                'image_url': listing.image_url,
                'product_type': listing.product_type,
                'created_at': listing.created_at.isoformat(),
                'is_for_rent': listing.is_for_rent,
                'is_softcopy': listing.is_softcopy,
                'faculty_name': listing.faculty_name
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/listings')
def get_listings():
    try:
        query = request.args.get('q', '')
        category = request.args.get('category', '')
        sort_by = request.args.get('sort_by', 'created_at')
        college = current_user.college if current_user.is_authenticated else ''

        # Base query with joins and initial filtering
        listings_query = Listing.query.join(User)
        if college:
            listings_query = listings_query.filter(User.college == college)

        # Search filters
        if query:
            listings_query = listings_query.filter(
                db.or_(
                    Listing.title.ilike(f'%{query}%'),
                    Listing.description.ilike(f'%{query}%'),
                    Listing.subject.ilike(f'%{query}%'),
                    Listing.faculty_name.ilike(f'%{query}%')
                )
            )

        # Category filter
        if category:
            listings_query = listings_query.filter(
                Listing.category.ilike(category)
            )

        # Sorting options
        sorting_options = {
            'price_low': Listing.price.asc(),
            'price_high': Listing.price.desc(),
            'recent': Listing.created_at.desc(),
            'softcopy': Listing.is_softcopy.desc()
        }
        listings_query = listings_query.order_by(
            sorting_options.get(sort_by, Listing.created_at.desc())
        )

        listings = listings_query.all()

        return jsonify({
            'listings': [{
                'id': l.id,
                'title': l.title,
                'description': l.description,
                'price': l.price,
                'rent_price': l.rent_price,
                'category': l.category,
                'condition': l.condition,
                'image_url': l.image_url,
                'is_for_rent': l.is_for_rent,
                'created_at': l.created_at.isoformat(),
                'seller': {
                    'id': l.seller.id,
                    'name': l.seller.full_name,
                    'college': l.seller.college
                },
                # Soft copy fields
                'is_softcopy': l.is_softcopy,
                'file_url': l.file_url,

                # Additional fields
                'product_type': l.product_type,
                'branch': l.branch,
                'study_year': l.study_year,
                'working_condition': l.working_condition,
                'warranty_status': l.warranty_status,
                'subject': l.subject,
                'faculty_name': l.faculty_name,
                'is_fake_warning': l.is_fake_warning
            } for l in listings]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def send_reset_email(email, token):
    try:
        msg = Message('Reset your EduTrade password',
                     sender=app.config['MAIL_USERNAME'],
                     recipients=[email])
        msg.body = f'Click the following link to reset your password: {url_for("reset_password", token=token, _external=True)}'
        mail.send(msg)
    except Exception as e:
        print(f"Error sending reset email: {str(e)}")
@app.route('/check-session')
def check_session():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': current_user.id,
                'email': current_user.email,
                'full_name': current_user.full_name,
                'department': current_user.department,
                'year': current_user.year,
                'is_admin': current_user.is_admin  # Add is_admin status
            }
        })
    return jsonify({'authenticated': False})
@app.route('/api/my-listings')
@login_required
def get_my_listings():
    try:
        listings = Listing.query.filter_by(seller_id=current_user.id).all()
        return jsonify({
            'listings': [{
                'id': l.id,
                'title': l.title,
                'description': l.description,
                'price': l.price,
                'category': l.category,
                'condition': l.condition,
                'image_url': l.image_url,
                'created_at': l.created_at.isoformat(),
                'product_type': l.product_type,
                'branch': l.branch,
                'study_year': l.study_year,
                'working_condition': l.working_condition,
                'warranty_status': l.warranty_status,
                'subject': l.subject,
                'is_fake_warning': l.is_fake_warning,
                'is_softcopy': l.is_softcopy,
                'file_url': l.file_url
            } for l in listings]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/wishlist')
@login_required
def get_wishlist():
    try:
        items = Wishlist.query.filter_by(user_id=current_user.id).all()
        return jsonify({
            'items': [{
                'id': item.id,
                'listing': {
                    'id': item.listing.id,
                    'title': item.listing.title,
                    'price': item.listing.price,
                    'image_url': item.listing.image_url,
                    'seller': {
                        'id': item.listing.seller.id,
                        'name': item.listing.seller.full_name
                    }
                },
                'created_at': item.created_at.isoformat()
            } for item in items]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/wishlist/add', methods=['POST'])
@login_required
def add_to_wishlist():
    try:
        listing_id = request.json.get('listing_id')
        if not listing_id:
            return jsonify({'error': 'Listing ID required'}), 400
            
        existing = Wishlist.query.filter_by(
            user_id=current_user.id,
            listing_id=listing_id
        ).first()
        
        if existing:
            return jsonify({'message': 'Item already in wishlist'})
            
        wishlist_item = Wishlist(
            user_id=current_user.id,
            listing_id=listing_id
        )
        
        db.session.add(wishlist_item)
        db.session.commit()
        
        return jsonify({'message': 'Added to wishlist successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/api/messages')
@login_required
def get_messages():
    try:
        other_user_id = request.args.get('other_user_id')
        listing_id = request.args.get('listing_id')

        query = MessageThread.query

        if other_user_id and listing_id:
            # Get specific conversation
            query = query.filter(
                MessageThread.listing_id == listing_id,
                db.or_(
                    db.and_(MessageThread.sender_id == current_user.id, MessageThread.receiver_id == other_user_id),
                    db.and_(MessageThread.sender_id == other_user_id, MessageThread.receiver_id == current_user.id)
                )
            )
        else:
            # Get all conversations
            query = query.filter(
                db.or_(
                    MessageThread.sender_id == current_user.id,
                    MessageThread.receiver_id == current_user.id
                )
            )

        messages = query.order_by(MessageThread.created_at.asc()).all()

        # Mark received messages as read
        unread_messages = [m for m in messages
                         if m.receiver_id == current_user.id and not m.read]
        for message in unread_messages:
            message.read = True

        if unread_messages:
            db.session.commit()

        return jsonify({
            'messages': [{
                'id': m.id,
                'content': m.content,
                'sender_id': m.sender_id,
                'receiver_id': m.receiver_id,
                'listing_id': m.listing_id,
                'created_at': m.created_at.isoformat(),
                'read': m.read,
                'sender': {
                    'id': m.sender.id,
                    'full_name': m.sender.full_name,
                    'profile_picture': m.sender.profile_picture
                },
                'receiver': {
                    'id': m.receiver.id,
                    'full_name': m.receiver.full_name,
                    'profile_picture': m.receiver.profile_picture
                }
            } for m in messages]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages/send', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.json

        # Validate required fields
        if not all(k in data for k in ['receiver_id', 'listing_id', 'content']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Create new message
        message = MessageThread(
            sender_id=current_user.id,
            receiver_id=data['receiver_id'],
            listing_id=data['listing_id'],
            content=data['content']
        )

        db.session.add(message)
        db.session.commit()

        return jsonify({
            'message': 'Message sent successfully',
            'data': {
                'id': message.id,
                'content': message.content,
                'sender_id': message.sender_id,
                'receiver_id': message.receiver_id,
                'listing_id': message.listing_id,
                'created_at': message.created_at.isoformat(),
                'read': message.read
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/api/messages/reply', methods=['POST'])
@login_required
def reply_to_message():
    try:
        data = request.json
        if not all(k in data for k in ['parent_message_id', 'content']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Get the parent message
        parent_message = db.session.get(MessageThread, data['parent_message_id'])
        if not parent_message:
            abort(404)

        # Create the reply
        reply = MessageThread(
            sender_id=current_user.id,
            receiver_id=parent_message.sender_id if parent_message.receiver_id == current_user.id else parent_message.receiver_id,
            listing_id=parent_message.listing_id,
            content=data['content'],
            parent_message_id=parent_message.id
        )

        db.session.add(reply)
        db.session.commit()

        return jsonify({
            'message': 'Reply sent successfully',
            'reply': {
                'id': reply.id,
                'content': reply.content,
                'sender': {
                    'id': reply.sender.id,
                    'name': reply.sender.full_name
                },
                'created_at': reply.created_at.isoformat()
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/api/messages/check-new')
@login_required
def check_new_messages():
    try:
        since = request.args.get('since')
        since_time = datetime.fromisoformat(since.replace('Z', '+00:00'))
        
        new_messages = MessageThread.query.filter(
            MessageThread.receiver_id == current_user.id,
            MessageThread.created_at > since_time,
            MessageThread.read == False
        ).all()
        
        return jsonify({
            'messages': [{
                'id': m.id,
                'content': m.content,
                'created_at': m.created_at.isoformat(),
                'sender': {
                    'id': m.sender.id,
                    'full_name': m.sender.full_name
                },
                'listing': {
                    'id': m.listing.id,
                    'title': m.listing.title
                }
            } for m in new_messages]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/listings/<int:listing_id>', methods=['DELETE'])
@login_required
def delete_listing(listing_id):
    try:
        listing = Listing.query.get_or_404(listing_id)
        
        # Check if the current user owns this listing
        if listing.seller_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Delete the image file if it exists
        if listing.image_url:
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], listing.image_url.split('/')[-1])
                if os.path.exists(image_path):
                    os.remove(image_path)
            except Exception as e:
                print(f"Error deleting image: {str(e)}")
        
        # Delete the listing
        db.session.delete(listing)
        db.session.commit()
        
        return jsonify({'message': 'Listing deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/my-listings')
@login_required
def my_listings_page():
    return send_file('index.html')
@app.route('/my-wishlist')
@login_required
def my_wishlist_page():
    return send_file('index.html')
@app.route('/api/wishlist/<int:wishlist_id>', methods=['DELETE'])
@login_required
def remove_from_wishlist(wishlist_id):
    try:
        wishlist_item = db.session.get(Wishlist, wishlist_id)
        if not wishlist_item:
            abort(404)
        
        # Check if the current user owns this wishlist item
        if wishlist_item.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.delete(wishlist_item)
        db.session.commit()
        
        return jsonify({'message': 'Item removed from wishlist successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
# Admin Routes
@app.route('/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.form
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        admin = db.session.execute(db.select(User).filter_by(email=email, is_admin=True)).scalar_one_or_none()

        if not admin or not admin.check_password(password):
            return jsonify({'error': 'Invalid admin credentials'}), 401

        login_user(admin)
        return jsonify({
            'message': 'Admin login successful',
            'admin': {
                'id': admin.id,
                'email': admin.email,
                'full_name': admin.full_name,
                'is_admin': True
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        users = User.query.all()
        listings = Listing.query.all()
        reports = Report.query.all()
        
        return jsonify({
            'users': [{
                'id': u.id,
                'email': u.email,
                'full_name': u.full_name,
                'college': u.college,
                
                'is_verified': u.is_verified,
                'created_at': u.created_at.isoformat(),
                'listings_count': len(u.listings)
            } for u in users],
            'listings': [{
                'id': l.id,
                'title': l.title,
                'price': l.price,
                'category': l.category,
                'seller_id': l.seller_id,
                'seller_name': l.seller.full_name,
                'created_at': l.created_at.isoformat(),
                'is_fake_warning': l.is_fake_warning
            } for l in listings],
            'reports': [{
                'id': r.id,
                'reporter_name': r.reporter.full_name,
                'listing_title': r.reported_listing.title if r.reported_listing else 'User Report',
                'status': r.status,
                'created_at': r.created_at.isoformat()
            } for r in reports],
            'stats': {
                'total_users': len(users),
                'total_listings': len(listings),
                'verified_users': len([u for u in users if u.is_verified]),
                'fake_warnings': len([l for l in listings if l.is_fake_warning]),
                'pending_reports': len([r for r in reports if r.status == 'pending']),
                'total_reports': len(reports)
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete-user/<int:user_id>', methods=['DELETE'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        user = db.session.get(User, user_id)
        if not user:
            abort(404)
        
        # First delete all notifications for this user
        Notification.query.filter_by(user_id=user_id).delete()
        
        # Then proceed with deleting other related data
        MessageThread.query.filter(
            db.or_(
                MessageThread.sender_id == user_id,
                MessageThread.receiver_id == user_id
            )
        ).delete(synchronize_session='fetch')
        
        Wishlist.query.filter_by(user_id=user_id).delete()
        Report.query.filter_by(reporter_id=user_id).delete()
        
        user_listings = Listing.query.filter_by(seller_id=user_id).all()
        for listing in user_listings:
            Report.query.filter_by(reported_listing_id=listing.id).delete()
            Wishlist.query.filter_by(listing_id=listing.id).delete()
            MessageThread.query.filter_by(listing_id=listing.id).delete()
            
            if listing.image_url:
                try:
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], listing.image_url.split('/')[-1])
                    if os.path.exists(image_path):
                        os.remove(image_path)
                except Exception as e:
                    print(f"Error deleting image for listing {listing.id}: {str(e)}")
            
            db.session.delete(listing)
        
        # Finally delete the user
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'User and their data deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete-listing/<int:listing_id>', methods=['DELETE'])
@login_required
def admin_delete_listing(listing_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        listing = db.session.get(Listing, listing_id)
        if not listing:
            abort(404)
        if not listing:
            abort(404)
        
        # Delete reports about this listing
        Report.query.filter_by(reported_listing_id=listing_id).delete()
        
        # Delete wishlist entries for this listing
        Wishlist.query.filter_by(listing_id=listing_id).delete()
        
        # Delete messages about this listing
        MessageThread.query.filter_by(listing_id=listing_id).delete()
        
        # Delete the listing's image file if it exists
        if listing.image_url:
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], listing.image_url.split('/')[-1])
                if os.path.exists(image_path):
                    os.remove(image_path)
            except Exception as e:
                print(f"Error deleting image for listing {listing_id}: {str(e)}")
        
        # Delete the listing itself
        db.session.delete(listing)
        db.session.commit()
        
        return jsonify({'message': 'Listing deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting listing {listing_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/toggle-verification/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_verification(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        user = db.session.get(User, user_id)
        if not user:
            abort(404)
        user.is_verified = not user.is_verified
        db.session.commit()
        
        return jsonify({
            'message': 'User verification status updated',
            'is_verified': user.is_verified
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/toggle-fake-warning/<int:listing_id>', methods=['POST'])
@login_required
def admin_toggle_fake_warning(listing_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        listing = db.session.get(Listing, listing_id)
        if not listing:
            abort(404)
        listing.is_fake_warning = not listing.is_fake_warning
        db.session.commit()
        
        return jsonify({
            'message': 'Fake warning status updated',
            'is_fake_warning': listing.is_fake_warning
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
# Add these new routes to app.py

@app.route('/admin/user-details/<int:user_id>')
@login_required
def admin_user_details(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        user = db.session.get(User, user_id)
        if not user:
            abort(404)
        return jsonify({
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'department': user.department,
            'year': user.year,
            'college': user.college,
            'profile_picture': user.profile_picture,
            'is_verified': user.is_verified,
            'created_at': user.created_at.isoformat(),
            'listings_count': len(user.listings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/user-listings/<int:user_id>')
@login_required
def admin_user_listings(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        listings = Listing.query.filter_by(seller_id=user_id).all()
        return jsonify([{
            'id': l.id,
            'title': l.title,
            'price': l.price,
            'image_url': l.image_url,
            'category': l.category,
            'condition': l.condition,
            'created_at': l.created_at.isoformat()
        } for l in listings])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/listing-details/<int:listing_id>')
@login_required
def admin_listing_details(listing_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        listing = db.session.get(Listing, listing_id)
        if not listing:
            abort(404)
        seller = User.query.get(listing.seller_id)
        return jsonify({
            'id': listing.id,
            'title': listing.title,
            'description': listing.description,
            'price': listing.price,
            'rent_price': listing.rent_price,
            'category': listing.category,
            'condition': listing.condition,
            'image_url': listing.image_url,
            'created_at': listing.created_at.isoformat(),
            'seller_id': listing.seller_id,
            'seller': {
                'id': seller.id,
                'full_name': seller.full_name,
                'email': seller.email
            },
            'product_type': listing.product_type,
            'branch': listing.branch,
            'study_year': listing.study_year,
            'working_condition': listing.working_condition,
            'warranty_status': listing.warranty_status,
            'subject': listing.subject,
            'is_fake_warning': listing.is_fake_warning,
            'is_softcopy': listing.is_softcopy,
            'file_url': listing.file_url
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Report Routes
@app.route('/api/report/create', methods=['POST'])
@login_required
def create_report():
    try:
        # Process image if provided
        if 'image' in request.files:
            image = request.files['image']
            if image.filename:
                image_url = save_image(image)
            else:
                image_url = None
        else:
            image_url = None

        # Description is required
        description = request.form.get('description')
        if not description:
            return jsonify({'error': 'Description is required'}), 400

        # Get IDs
        listing_id = request.form.get('listing_id')
        message_thread_id = request.form.get('message_thread_id')
        
        # Check if this is a temporary message thread ID
        is_temp_id = message_thread_id and message_thread_id.startswith('temp_')
        
        # For temporary IDs, we don't need an existing message thread
        if is_temp_id:
            message_thread_id = None
        
        # Require at least one ID or a description
        if not description:
            return jsonify({'error': 'Description is required'}), 400
        
        # Create the report
        report = Report(
            reporter_id=current_user.id,
            reported_listing_id=listing_id if listing_id else None,
            message_thread_id=message_thread_id if message_thread_id else None,
            description=description,
            image_url=image_url
        )
        
        db.session.add(report)
        db.session.commit()
        
        return jsonify({
            'message': 'Report submitted successfully',
            'report_id': report.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reports')
@login_required
def admin_get_reports():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        reports = Report.query.order_by(Report.created_at.desc()).all()
        reports_data = []
        
        for r in reports:
            report_data = {
                'id': r.id,
                'reporter': {
                    'id': r.reporter.id,
                    'name': r.reporter.full_name,
                    'email': r.reporter.email
                },
                'description': r.description,
                'image_url': r.image_url,
                'status': r.status,
                'created_at': r.created_at.isoformat()
            }
            
            # Add listing info if available
            if r.reported_listing_id and r.reported_listing:
                report_data['listing'] = {
                    'id': r.reported_listing.id,
                    'title': r.reported_listing.title
                }
            else:
                report_data['listing'] = None
                
            # Add message info if available
            if r.message_thread_id and r.message_thread:
                report_data['message'] = {
                    'id': r.message_thread.id,
                    'sender_name': r.message_thread.sender.full_name,
                    'receiver_name': r.message_thread.receiver.full_name
                }
            else:
                report_data['message'] = None
                
            reports_data.append(report_data)
        
        return jsonify({'reports': reports_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reports/<int:report_id>')
@login_required
def admin_get_report_details(report_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        report = Report.query.get_or_404(report_id)
        response_data = {
            'id': report.id,
            'reporter': {
                'id': report.reporter.id,
                'name': report.reporter.full_name,
                'email': report.reporter.email,
                'college': report.reporter.college
            },
            'description': report.description,
            'image_url': report.image_url,
            'status': report.status,
            'created_at': report.created_at.isoformat()
        }
        
        # Add listing info if it exists
        if report.reported_listing_id and report.reported_listing:
            response_data['listing'] = {
                'id': report.reported_listing.id,
                'title': report.reported_listing.title,
                'seller': {
                    'id': report.reported_listing.seller.id,
                    'name': report.reported_listing.seller.full_name,
                    'email': report.reported_listing.seller.email
                }
            }
        else:
            response_data['listing'] = None
            
        # Add message thread info if it exists
        if report.message_thread_id and report.message_thread:
            response_data['message_thread'] = {
                'id': report.message_thread.id,
                'content': report.message_thread.content,
                'sender': {
                    'id': report.message_thread.sender.id,
                    'name': report.message_thread.sender.full_name
                },
                'receiver': {
                    'id': report.message_thread.receiver.id,
                    'name': report.message_thread.receiver.full_name
                }
            }
        else:
            response_data['message_thread'] = None
            
        return jsonify(response_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reports/<int:report_id>/status', methods=['POST'])
@login_required
def admin_update_report_status(report_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        report = Report.query.get_or_404(report_id)
        new_status = request.json.get('status')
        
        if new_status not in ['pending', 'reviewed', 'resolved']:
            return jsonify({'error': 'Invalid status'}), 400
            
        report.status = new_status
        db.session.commit()
        
        return jsonify({
            'message': 'Report status updated successfully',
            'status': report.status
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Create admin user on startup
def create_admin_user():
    try:
        # Check if admin already exists
        admin = User.query.filter_by(email='admin@studentsmart.co.in').first()
        
        if not admin:
            admin_user = User(
                email='admin@studentsmart.co.in',
                full_name='Admin User',
                department='Admin',
                year=1,
                college='Admin College',
                is_verified=True,
                is_admin=True
            )
            admin_user.set_password('MentorlyXVemuXRcee@')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully")
        else:
            print("Admin user already exists")
    except Exception as e:
        db.session.rollback()
        print(f"Admin user creation failed or already exists: {str(e)}")
@app.route('/debug/files/<int:listing_id>')
@login_required
def debug_file_paths(listing_id):
    """Debug route to diagnose file path issues"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        listing = Listing.query.get_or_404(listing_id)
        result = {
            'listing_id': listing.id,
            'title': listing.title,
            'is_softcopy': listing.is_softcopy,
            'file_url': listing.file_url,
            'app_root': app.root_path,
            'cwd': os.getcwd(),
            'upload_folder': app.config['UPLOAD_FOLDER'],
            'paths_checked': []
        }
        
        if listing.is_softcopy and listing.file_url:
            # Get filename
            if listing.file_url.startswith('uploads/'):
                file_name = listing.file_url.split('/')[-1]
            else:
                file_name = listing.file_url
                
            result['extracted_filename'] = file_name
            
            # Check various paths
            paths_to_check = [
                os.path.join(app.root_path, 'static', 'uploads', file_name),
                os.path.join('static', 'uploads', file_name),
                os.path.join(os.getcwd(), 'static', 'uploads', file_name),
                os.path.join(app.root_path, 'static', listing.file_url),
                os.path.join(os.getcwd(), 'static', listing.file_url)
            ]
            
            for path in paths_to_check:
                exists = os.path.exists(path)
                result['paths_checked'].append({
                    'path': path,
                    'exists': exists,
                    'is_file': os.path.isfile(path) if exists else False,
                    'is_dir': os.path.isdir(path) if exists else False,
                    'size': os.path.getsize(path) if exists and os.path.isfile(path) else None
                })
                
            # List the static/uploads directory to see what's there
            uploads_dir = os.path.join(app.root_path, 'static', 'uploads')
            if os.path.exists(uploads_dir):
                result['uploads_dir_contents'] = os.listdir(uploads_dir)
            else:
                result['uploads_dir_contents'] = "Directory not found"
        
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/debug/system')
@login_required
def debug_system():
    """Debug route to check system configuration and ensure directories exist"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        result = {
            'app_info': {
                'root_path': app.root_path,
                'static_folder': app.static_folder,
                'upload_folder_config': app.config['UPLOAD_FOLDER'],
                'current_directory': os.getcwd()
            },
            'directories': {},
            'actions_taken': []
        }
        
        # Check and create necessary directories
        directories_to_check = [
            app.config['UPLOAD_FOLDER'],
            os.path.join(app.root_path, 'static', 'uploads'),
            os.path.join('static', 'uploads'),
        ]
        
        for directory in directories_to_check:
            exists = os.path.exists(directory)
            is_dir = os.path.isdir(directory) if exists else False
            
            result['directories'][directory] = {
                'exists': exists,
                'is_directory': is_dir
            }
            
            # Create the directory if it doesn't exist
            if not exists:
                try:
                    os.makedirs(directory, exist_ok=True)
                    result['actions_taken'].append(f"Created directory: {directory}")
                    result['directories'][directory]['exists'] = True
                    result['directories'][directory]['is_directory'] = True
                except Exception as e:
                    result['actions_taken'].append(f"Failed to create {directory}: {str(e)}")
        
        # Run the path fixing code directly
        try:
            listings = Listing.query.filter(Listing.is_softcopy == True).filter(Listing.file_url.isnot(None)).all()
            updated_count = 0
            
            for listing in listings:
                if listing.file_url and listing.file_url.startswith('uploads/'):
                    # Get just the filename
                    filename = listing.file_url.split('/')[-1]
                    result['actions_taken'].append(f"Fixing path for listing #{listing.id}: {listing.file_url} -> {filename}")
                    listing.file_url = filename
                    updated_count += 1
            
            if updated_count > 0:
                db.session.commit()
                result['actions_taken'].append(f"Fixed {updated_count} file paths in database")
            else:
                result['actions_taken'].append("No file paths needed fixing in database")
        except Exception as e:
            db.session.rollback()
            result['actions_taken'].append(f"Error fixing file paths: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/download/<int:listing_id>')
@login_required
def download_file(listing_id):
    """Download a softcopy file"""
    try:
        # Get the listing
        listing = db.session.get(Listing, listing_id)
        if not listing:
            abort(404)

        print(f"\n\n===== DOWNLOAD REQUEST for listing ID: {listing_id} =====")
        print(f"Listing info: {listing.title}, is_softcopy: {listing.is_softcopy}, file_url: {listing.file_url}")
        
        # Check if it's a softcopy
        if not listing.is_softcopy:
            print(f"Listing {listing_id} is not a softcopy")
            abort(404)
            
        # Get the filename from file_url
        file_url = listing.file_url
        if not file_url:
            print(f"Listing {listing_id} has no file_url")
            abort(404)
            
        # Extract just the filename regardless of format
        if '/' in file_url:
            file_name = file_url.split('/')[-1] 
        else:
            file_name = file_url
            
        print(f"Looking for file: {file_name}")
        
        # Check for working files to find the correct directory
        test_filenames = [
            "2881bee4-a0ee-4efe-ae76-4dd654b79429_NLP_Exam_Preparation_Topics.pdf",
            "603f8fa0-0fa4-4295-a383-81dd385778e2_N_L_RAM_CHARAN_TEJA.pdf"
        ]
        
        working_file_paths = []
        for test_file in test_filenames:
            possible_locations = [
                os.path.join(app.root_path, 'static', 'uploads', test_file),
                os.path.join(os.getcwd(), 'static', 'uploads', test_file),
                os.path.join('static', 'uploads', test_file)
            ]
            
            for location in possible_locations:
                if os.path.exists(location):
                    working_file_paths.append(location)
                    
        if working_file_paths:
            print(f"Found working files at: {working_file_paths}")
            working_dir = os.path.dirname(working_file_paths[0])
            print(f"Using working directory: {working_dir}")
            file_path = os.path.join(working_dir, file_name)
            print(f"Checking for file at: {file_path}")
            if os.path.exists(file_path):
                print(f"File found at working directory path: {file_path}")
                
                # Get the file extension for MIME type
                _, file_ext = os.path.splitext(file_path)
                file_ext = file_ext.lower()
                
                # Set the appropriate MIME type
                if file_ext == '.pdf':
                    mimetype = 'application/pdf'
                elif file_ext == '.doc':
                    mimetype = 'application/msword'
                elif file_ext == '.docx':
                    mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                elif file_ext == '.txt':
                    mimetype = 'text/plain'
                elif file_ext in ['.ppt', '.pptx']:
                    mimetype = 'application/vnd.ms-powerpoint'
                elif file_ext in ['.xls', '.xlsx']:
                    mimetype = 'application/vnd.ms-excel'
                else:
                    mimetype = 'application/octet-stream'
                    
                # Download the file
                download_name = f"{secure_filename(listing.title)}{file_ext}"
                print(f"Sending file {file_path} as {download_name} with mimetype {mimetype}")
                
                return send_file(
                    file_path,
                    as_attachment=True,
                    download_name=download_name,
                    mimetype=mimetype
                )
        
        # Try all possible locations if working directory approach failed
        print("Working directory approach failed, trying all possible paths")
        
        # Search in multiple locations
        possible_paths = [
            os.path.join(app.root_path, 'static', 'uploads', file_name),
            os.path.join(os.getcwd(), 'static', 'uploads', file_name),
            os.path.join('static', 'uploads', file_name),
            os.path.join(app.root_path, 'static', file_url),
            os.path.join(os.getcwd(), 'static', file_url)
        ]
        
        print(f"Trying paths: {possible_paths}")
        
        file_path = None
        for path in possible_paths:
            print(f"Checking: {path}")
            if os.path.exists(path):
                file_path = path
                print(f"Found at: {file_path}")
                break
        
        if not file_path:
            # If still not found, search recursively
            print("File not found in standard paths, searching recursively")
            
            search_dirs = [
                os.path.join(app.root_path, 'static'),
                os.path.join(os.getcwd(), 'static')
            ]
            
            for search_dir in search_dirs:
                if os.path.exists(search_dir):
                    print(f"Searching directory: {search_dir}")
                    for root, dirs, files in os.walk(search_dir):
                        if file_name in files:
                            file_path = os.path.join(root, file_name)
                            print(f"Found through recursive search: {file_path}")
                            break
                if file_path:
                    break
        
        if not file_path:
            print("File not found after exhaustive search")
            abort(404)
        
        # Get the file extension for MIME type
        _, file_ext = os.path.splitext(file_path)
        file_ext = file_ext.lower()
        
        # Set the appropriate MIME type
        if file_ext == '.pdf':
            mimetype = 'application/pdf'
        elif file_ext == '.doc':
            mimetype = 'application/msword'
        elif file_ext == '.docx':
            mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        elif file_ext == '.txt':
            mimetype = 'text/plain'
        elif file_ext in ['.ppt', '.pptx']:
            mimetype = 'application/vnd.ms-powerpoint'
        elif file_ext in ['.xls', '.xlsx']:
            mimetype = 'application/vnd.ms-excel'
        else:
            mimetype = 'application/octet-stream'
            
        # Download the file
        download_name = f"{secure_filename(listing.title)}{file_ext}"
        print(f"Sending file {file_path} as {download_name} with mimetype {mimetype}")
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=download_name,
            mimetype=mimetype
        )
    
    except Exception as e:
        print(f"Error in download_file: {str(e)}")
        import traceback
        traceback.print_exc()
        abort(500)

@app.route('/debug/dirs')
def debug_directories():
    """Debug route to show directory structure"""
    try:
        result = {
            "app_info": {
                "root_path": app.root_path,
                "static_folder": app.static_folder,
                "upload_folder_config": app.config['UPLOAD_FOLDER'],
                "current_directory": os.getcwd()
            },
            "directory_tree": {}
        }
        
        # Check key directories
        key_dirs = [
            os.path.join(app.root_path, 'static'),
            os.path.join(app.root_path, 'static', 'uploads'),
            app.config['UPLOAD_FOLDER'],
            os.path.join(os.getcwd(), 'static'),
            os.path.join(os.getcwd(), 'static', 'uploads')
        ]
        
        # Check if directories exist and list their contents
        for directory in key_dirs:
            if os.path.exists(directory):
                result["directory_tree"][directory] = {
                    "exists": True,
                    "is_dir": os.path.isdir(directory),
                    "contents": os.listdir(directory) if os.path.isdir(directory) else None
                }
            else:
                result["directory_tree"][directory] = {
                    "exists": False
                }
        
        # Also list all softcopy listings
        with app.app_context():
            result["softcopy_listings"] = [
                {
                    "id": l.id,
                    "title": l.title,
                    "file_url": l.file_url,
                    "created_at": l.created_at.isoformat() if l.created_at else None
                }
                for l in Listing.query.filter_by(is_softcopy=True).all()
            ]
        
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/debug/fix-file/<int:listing_id>')
@login_required
def debug_fix_file(listing_id):
    """Debug route to fix a file location for a specific listing"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        result = {
            "listing_id": listing_id,
            "actions": []
        }
        
        # Find the listing
        listing = db.session.get(Listing, listing_id)
        if not listing:
            abort(404)
        result["listing_info"] = {
            "id": listing.id,
            "title": listing.title,
            "is_softcopy": listing.is_softcopy,
            "file_url": listing.file_url
        }
        
        if not listing.is_softcopy or not listing.file_url:
            return jsonify({"error": "Listing is not a softcopy or has no file URL"}), 400
        
        # Get filenames
        if '/' in listing.file_url:
            file_name = listing.file_url.split('/')[-1]
            result["actions"].append(f"Extracted filename {file_name} from {listing.file_url}")
            
            # Update the database to store just the filename
            old_file_url = listing.file_url
            listing.file_url = file_name
            db.session.commit()
            result["actions"].append(f"Updated database entry from {old_file_url} to {file_name}")
        else:
            file_name = listing.file_url
        
        # Find the file
        file_found = False
        found_path = None
        
        # List of places to look for the file
        search_locations = [
            app.root_path,
            os.getcwd(),
            os.path.join(app.root_path, 'static'),
            os.path.join(os.getcwd(), 'static')
        ]
        
        # Search for the file
        for location in search_locations:
            for root, dirs, files in os.walk(location):
                if file_name in files:
                    found_path = os.path.join(root, file_name)
                    file_found = True
                    result["actions"].append(f"Found file at {found_path}")
                    break
            if file_found:
                break
        
        if not file_found:
            result["actions"].append(f"File not found in any location")
            return jsonify(result), 404
        
        # Ensure target directory exists
        target_dir = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(target_dir, exist_ok=True)
        result["actions"].append(f"Ensured target directory exists: {target_dir}")
        
        # Copy the file to the target location if it's not already there
        target_path = os.path.join(target_dir, file_name)
        if os.path.abspath(found_path) != os.path.abspath(target_path):
            import shutil
            shutil.copy2(found_path, target_path)
            result["actions"].append(f"Copied file from {found_path} to {target_path}")
            
            # Verify the copy was successful
            if os.path.exists(target_path):
                result["actions"].append(f"Verified file exists at target location")
                result["success"] = True
            else:
                result["actions"].append(f"Failed to copy file to target location")
                result["success"] = False
        else:
            result["actions"].append(f"File is already in the correct location")
            result["success"] = True
        
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/cofundersprofiles.html')
def cofounders_profile():
    return send_file('cofundersprofiles.html')
# Email Configuration (add with your other configs)


# Notification Endpoint
@app.route('/api/send_message_notification', methods=['POST'])
@login_required
def send_message_notification():
    print("\n=== NOTIFICATION ENDPOINT HIT ===")  # Debug log
    try:
        data = request.get_json()
        print("Received data:", data)  # Debug log
        
        if not data:
            print("No data received")  # Debug log
            return jsonify({'error': 'No data provided'}), 400

        recipient = db.session.get(User, data.get('recipient_id'))
        sender = db.session.get(User, data.get('sender_id'))
        listing = db.session.get(Listing, data.get('listing_id'))

        if not all([recipient, sender, listing]):
            print("Missing recipient, sender, or listing")  # Debug log
            return jsonify({'error': 'Invalid recipient, sender, or listing'}), 404

        print(f"Preparing email to {recipient.email}")  # Debug log
        
        # Create email with improved HTML template
        msg = Message(
            subject=f"New Message About Your Listing: {listing.title}",
            recipients=[recipient.email],
            html=f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #2563eb;">New Message on StudentsMart</h2>
                <p>You've received a new message about your listing:</p>
                <div style="background: #f3f4f6; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    <h3 style="margin-top: 0;">{listing.title}</h3>
                    <p><strong>From:</strong> {sender.full_name} ({sender.college})</p>
                </div>
                <a href="{url_for('index', _external=True)}" 
                   style="display: inline-block; padding: 10px 20px; background: #2563eb; 
                          color: white; text-decoration: none; border-radius: 5px;">
                    View Message
                </a>
                <p style="margin-top: 20px; color: #6b7280; font-size: 12px;">
                    This is an automated notification. Please do not reply directly to this email.
                </p>
            </div>
            """
        )

        # Improved email sending with better error handling
        def send_async_email(app, msg):
            with app.app_context():
                try:
                    print("Attempting to send email...")  # Debug log
                    mail.send(msg)
                    print("Email sent successfully!")  # Debug log
                except Exception as e:
                    print(f"Failed to send email: {str(e)}")  # Debug log
                    # Log full error details for debugging
                    app.logger.error(f"Email sending failed: {str(e)}")
                    if hasattr(e, 'smtp_error'):
                        app.logger.error(f"SMTP error: {e.smtp_error}")

        # Start thread with error handling
        try:
            Thread(target=send_async_email, args=(app, msg)).start()
        except Exception as e:
            print(f"Failed to start email thread: {str(e)}")
            return jsonify({'error': 'Failed to queue email'}), 500
        
        return jsonify({
            'success': True,
            'message': 'Notification queued for sending'
        })

    except Exception as e:
        error_msg = f"Notification processing error: {str(e)}"
        print(error_msg)  # Debug log
        app.logger.error(error_msg)
        return jsonify({
            'error': 'Failed to process notification',
            'details': str(e)
        }), 500
@app.route('/<filename>')
def serve_html(filename):
    if filename.endswith('.html') and os.path.exists(filename):
        return send_file(filename)
    else:
        return "File not found", 404
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        
       
    app.run(host="0.0.0.0", port=80,debug=True)
