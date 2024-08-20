from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from pymongo import MongoClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from bson.objectid import ObjectId  # Import ObjectId for generating unique IDs
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'your_secret_key'

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['secure_file_storage']

access_requests = db['access_requests']
shared_files = db['shared_files']

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        db.users.insert_one({'username': username, 'password': hashed_password})
        session['username'] = username  # Store username in session for future steps
        return redirect(url_for('set_file_password'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.users.find_one({'username': username})
        if user:
            # Check if the password matches the hashed password
            if check_password_hash(user['password'], password):
                session['username'] = username
                return redirect(url_for('home'))
            else:
                flash('Incorrect password. Please try again.', 'error')
        else:
            flash('Username not found. Please try again or register.', 'error')
    return render_template('login.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/files')
def files():
    if 'username' not in session:
        return redirect(url_for('login'))
    user_files = db.files.find({'username': session['username']})
    return render_template('files.html', user_files=user_files)

@app.route('/set_file_password', methods=['GET', 'POST'])
def set_file_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file_password = request.form['file_password']
        hashed_file_password = generate_password_hash(file_password)
        db.users.update_one({'username': session['username']}, {'$set': {'file_password': hashed_file_password}})
        return redirect(url_for('home'))
    return render_template('set_file_password.html')

# Derive key from password using PBKDF2
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)  # AES key length is 32 bytes (256 bits)

# Encrypt file using AES in CBC mode
def encrypt_file(file_path, file_password):
    # Generate a random salt
    salt = os.urandom(16)

    # Derive key using PBKDF2
    key = derive_key(file_password.encode('utf-8'), salt)

    # Initialize AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)

    # Read plaintext from file
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Pad plaintext to be multiple of AES block size
    padded_plaintext = pad(plaintext, AES.block_size)

    # Encrypt plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Write salt and ciphertext to encrypted file
    with open(file_path + '.enc', 'wb') as f:
        f.write(salt)
        f.write(ciphertext)

def decrypt_file(file_path, file_password):
    try:
        # Read salt and ciphertext from encrypted file
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            ciphertext = f.read()

        # Derive key using PBKDF2
        key = derive_key(file_password.encode('utf-8'), salt)

        # Initialize AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC)

        # Decrypt ciphertext
        plaintext = cipher.decrypt(ciphertext)

        # Unpad decrypted plaintext
        unpadded_plaintext = unpad(plaintext, AES.block_size)

        # Write decrypted plaintext to file
        with open(file_path[:-4], 'wb') as f:  # Remove '.enc' extension from filename
            f.write(unpadded_plaintext)

        print("Decryption successful.")
    except Exception as e:
        print("Decryption failed:", e)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user = db.users.find_one({'username': session['username']})
        if not user:
            flash('User not found. Please login again.')
            return redirect(url_for('login'))

        file_password = request.form.get('file_password')

        # Check if file password matches the stored hashed file password
        if 'file_password' in user:
            if not check_password_hash(user['file_password'], file_password):
                flash('Invalid file password. Please try again.')
                return redirect(url_for('upload_file'))
        else:
            flash('File password not set. Please set your file password first.')
            return redirect(url_for('set_file_password'))

        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Encrypt the uploaded file using the user's file password
            encrypt_file(file_path, file_password)

            db.files.insert_one({'username': session['username'], 'filename': filename})
            return redirect(url_for('index'))

    return render_template('upload.html')

@app.route('/download/<filename>', methods=['GET', 'POST'])
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = db.users.find_one({'username': session['username']})
    if 'file_password' in user:
        if request.method == 'GET':
            return render_template('enter_file_password.html', filename=filename)
        elif request.method == 'POST':
            file_password = request.form['file_password']
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Check if the provided file_password matches the hashed file_password stored in the database
            if not check_password_hash(user['file_password'], file_password):
                # If the provided file_password doesn't match, inform the user and redirect back
                flash('Incorrect file password. Please try again.')
                return redirect(url_for('download_file', filename=filename))

            # Decrypt the file using the user's file password
            try:
                decrypt_file(file_path, file_password)
                # If decryption was successful, serve the decrypted file
                return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
            except Exception as e:
                # If decryption failed, inform the user
                flash('Failed to decrypt the file. Please try again.')
                return redirect(url_for('download_file', filename=filename))
    else:
        return "File password not set. Please set your file password first."




from flask import abort, send_file
@app.route('/download_file_with_status_check/<filename>', methods=['GET'])
def download_file_with_status_check(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    shared_file = db.shared_files.find_one({'filename': filename, 'recipient_username': session['username']})
    if shared_file:
        status = shared_file.get('status')
        if status == 'pending':
            # If status is pending, redirect to request_enter_file_password page
            return redirect(url_for('request_enter_file_password', shared_file_id=str(shared_file['_id']), filename=filename))
        elif status == 'approved':
            # If status is approved, proceed with decryption using sender's file password
            sender_username = shared_file['sender']
            sender = db.users.find_one({'username': sender_username})
            if sender and 'file_password' in sender:
                # Decrypt the file using sender's file password
                encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
                decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                decrypt_file(encrypted_file_path, sender['file_password'])
                
                # Re-encrypt the file using receiver's file password
                receiver = db.users.find_one({'username': session['username']})
                if receiver and 'file_password' in receiver:
                    encrypt_file(decrypted_file_path, receiver['file_password'])
                    
                    # Enable the link for download
                    return render_template('receivers_enter_file_password.html', filename=filename, shared_file_id=str(shared_file['_id']))
                else:
                    flash('Receiver not found or receiver file password not set.', 'error')
                    abort(404)
            else:
                flash('Sender not found or sender file password not set.', 'error')
                abort(404)
        elif status == 'in_progress':
            # If status is in_progress, display a message indicating that the request has already been sent
            flash('The request has already been sent for this file. Please wait for access.', 'info')
            # Redirect back to the received_files page or any other appropriate page
            return redirect(url_for('received_files'))
        else:
            # If status is neither pending nor in_progress, abort with a 404 error
            abort(404)
    else:
        # If shared file not found, abort with a 404 error
        abort(404)



from flask import render_template, abort, send_file
@app.route('/view_decrypted_file/<filename>/<share_id>', methods=['POST'])
def view_decrypted_file(filename, share_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    file_password = request.form.get('file_password')
    user = db.users.find_one({'username': session['username']})
    
    if 'file_password' in user:
        if check_password_hash(user['file_password'], file_password):
            # Decrypt the file using the user's file password
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            decrypted_content = decrypt_and_get_content(file_path, file_password)
            
            if decrypted_content:
                # Render a template to display the decrypted file content
                return render_template('view_decrypted_content.html', content=decrypted_content, filename=filename, file_password=file_password, share_id=share_id)
            else:
                # If decryption failed, inform the user
                flash('Failed to decrypt the file. Please try again.', 'error')
                return redirect(url_for('download_file', filename=filename))
        else:
            # If the provided file password is incorrect, inform the user and redirect back
            flash('Incorrect file password. Please try again.', 'error')
            return redirect(url_for('download_file', filename=filename))
    else:
        return "File password not set. Please set your file password first."


from flask import redirect

@app.route('/receivers_enter_file_password/<filename>/<shared_file_id>', methods=['GET', 'POST'])
def receivers_enter_file_password(filename, shared_file_id):
    if request.method == 'POST':
        file_password = request.form.get('file_password')
        receiver = db.users.find_one({'username': session['username']})
        if receiver and 'file_password' in receiver:
            if check_password_hash(receiver['file_password'], file_password):
                # If the password is correct, decrypt the file using the receiver's file password
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                decrypt_file(file_path, file_password)
                # Serve the decrypted file for download
                return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
            else:
                flash('Incorrect file password. Please try again.', 'error')
                return redirect(url_for('receivers_enter_file_password', filename=filename, shared_file_id=shared_file_id))
        else:
            flash('Receiver not found or receiver file password not set.', 'error')
            abort(404)

    return render_template('receivers_enter_file_password.html', filename=filename, shared_file_id=shared_file_id)

@app.route('/received_files')
def received_files():
    if 'username' not in session:
        return redirect(url_for('login'))

    received_files = db.shared_files.find({'recipient_username': session['username']})
    return render_template('received_files.html', received_files=received_files)


@app.route('/notifications')
def notifications():
    # Fetch notifications for the current user (sender)
    sender_username = session['username']
    notifications = db.access_requests.find({'sender': sender_username})

    return render_template('notifications.html', notifications=notifications)



@app.route('/share', methods=['GET', 'POST'])
def share():
    if 'username' not in session:
        return redirect(url_for('login'))

    user_files = db.files.find({'username': session['username']})

    if request.method == 'POST':
        recipient_username = request.form.get('recipient_username')
        file_password = request.form.get('file_password')
        filename = request.form.get('filename')

        recipient = db.users.find_one({'username': recipient_username})
        if not recipient:
            flash('Recipient is not a registered user.', 'error')
            return render_template('share.html', user_files=user_files)

        sender = db.users.find_one({'username': session['username']})
        if 'file_password' in sender:
            if not check_password_hash(sender['file_password'], file_password):
                flash('Invalid file password. Please try again.', 'error')
                return render_template('share.html', user_files=user_files)
        else:
            flash('File password not set. Please set your file password first.', 'error')
            return render_template('share.html', user_files=user_files)

        # Generate unique ID for the shared file
        shared_file_id = ObjectId()

        # Store shared file information in the database with status set to "pending"
        db.shared_files.insert_one({
            '_id': shared_file_id,
            'sender': session['username'],
            'recipient_username': recipient_username,
            'filename': filename,
            'status': 'pending'  # Initial status set to "pending"
        })

        flash('File shared successfully with {}'.format(recipient_username), 'success')

    return render_template('share.html', user_files=user_files)

@app.route('/request_enter_file_password/<shared_file_id>', methods=['GET', 'POST'])
def request_enter_file_password(shared_file_id):
    if request.method == 'POST':
        file_password = request.form.get('file_password')

        # Retrieve the shared file's information using its unique identifier
        shared_file = db.shared_files.find_one({'_id': ObjectId(shared_file_id)})
        recipient_username = shared_file['recipient_username']

        # Retrieve the recipient's information from the database
        recipient = db.users.find_one({'username': recipient_username})
        recipient_hashed_password = recipient.get('file_password')

        # Validate file password and update status if valid
        if recipient_hashed_password and check_password_hash(recipient_hashed_password, file_password):
            # If the password is correct, update the status to "in_progress"
            db.shared_files.update_one({'_id': ObjectId(shared_file_id)}, {'$set': {'status': 'in_progress'}})
            flash('File password validated successfully. Status updated to "in_progress".', 'success')

            # Store notification information in the database
            notification_id = ObjectId()
            db.access_requests.insert_one({
                '_id': notification_id,
                'sender': shared_file['sender'],
                'recipient_username': recipient_username,
                'filename': shared_file['filename'],
                'shared_file_id': shared_file_id,
                'status': 'pending'
            })

            # Display the success message and redirect to the received_files page
            flash('Request successfully sent.', 'success')
            return redirect(url_for('received_files'))

        else:
            # If the password is incorrect, inform the user and do not change the status
            flash('Invalid file password. Please try again.', 'error')
            return redirect(url_for('request_enter_file_password', shared_file_id=shared_file_id))

    return render_template('request_enter_file_password.html', shared_file_id=shared_file_id)

@app.route('/allow_access/<notification_id>', methods=['POST'])
def allow_access(notification_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Retrieve the shared file's ID from the notification
    notification = db.access_requests.find_one({'_id': ObjectId(notification_id)})
    shared_file_id = notification['shared_file_id']

    # Update the status of the shared file to "approved" in the shared_files collection
    db.shared_files.update_one({'_id': ObjectId(shared_file_id)}, {'$set': {'status': 'approved'}})

    # Delete the notification from the access_requests collection
    db.access_requests.delete_one({'_id': ObjectId(notification_id)})

    # Redirect back to the notifications page
    return redirect(url_for('notifications'))


@app.route('/deny_access/<notification_id>', methods=['POST'])
def deny_access(notification_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Retrieve the shared file's ID from the notification
    notification = db.access_requests.find_one({'_id': ObjectId(notification_id)})
    shared_file_id = notification['shared_file_id']

    # Update the status of the shared file to "pending" in the shared_files collection
    db.shared_files.update_one({'_id': ObjectId(shared_file_id)}, {'$set': {'status': 'pending'}})

    # Delete the notification from the access_requests collection
    db.access_requests.delete_one({'_id': ObjectId(notification_id)})

    # Redirect back to the notifications page
    return redirect(url_for('notifications'))



@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/get_file/<filename>')
def get_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
