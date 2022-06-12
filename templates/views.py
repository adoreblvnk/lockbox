import binascii
import datetime as dt
import hashlib
import os
import shelve
import time as Support_Vector
from email.mime import image
from pathlib import Path

from dotenv import load_dotenv
from flask import (abort, flash, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from flask_jwt import JWT, current_identity, jwt_required
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
from flask_socketio import SocketIO, emit
from twilio.rest import Client  # Aden
from werkzeug.utils import secure_filename

import file_handler
import forms
from forms import LoginForm, RegisterForm
from main import app


DB_PATH = "database/lockbox.db"


# set environment variables
load_dotenv()
DB_PATH = os.getenv("DB_PATH")

# Aden: Implement ReCaptcha
# reCaptcha site: https://www.google.com/recaptcha/
app.config["RECAPTCHA_PUBLIC_KEY"] = os.getenv("RECAPTCHA_PUBLIC_KEY")
app.config["RECAPTCHA_PRIVATE_KEY"] = os.getenv("RECAPTCHA_PRIVATE_KEY")

# Aden: Implement Twilio 2fa
# client format: Client("<account SID>", "<auth token>")
client = Client(os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTHTOKEN"))
verify = client.verify.services(os.getenv("TWILIO_VERIFY_SID"))

# NOTE: do NOT refactor this.
# josef: import routes
from jx_api import FileMetadata, VersionControl
from jx_routes import *
from aden import *

# Mark's Stuff
from Mark_AFC import *

# Edwins Stuff
from edwin import *


def user_logged_in():
    # session['username'] = 'peter'
    # return True
    return 'username' in session


# Aden: register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        username = request.form["username"]

        # Check if username exists
        with shelve.open(DB_PATH, "r") as db:
            if username in db["login"]:
                flash("The username already exists", "info")
                return redirect("/register")

        # # Edwin: Facial Recognition
        # image = request.form.get('submitPhoto')
        # status = rs(username, image)
        # print('Register status:', status)
        # if status == "Registration fail" or status == "Image not clear! Please try again!":
        #     flash(status, "info")
        #     return redirect("/register")

        # josef, aden: SVC password
        import re

        from sklearn import svm
        with open(r'SupportVectorMachine\test.txt', 'w+') as test:
            testData = str(request.form["password"]) + '|' + str(2)
            print(testData)
            test.write(testData)
        # Returns feature & label arrays [ feature, label ]

        def parseData(data):
            features = list()
            labels = list()
            passwords = list()
            with open(data) as f:
                for line in f:
                    if line != "":
                        both = line.replace('\n', '').split("|")
                        password = both[0]
                        label = both[1]
                        feature = [0, 0, 0, 0, 0]
                        # FEATURES
                        lenMin = False  # more than 8 chars
                        specChar = False  # special character
                        ucChar = False  # uppercase character
                        numChar = False  # numeric character
                        # More than 8 characters
                        if len(password) > 8:
                            lenMin = True
                        # Special Character
                        specialMatch = re.search(
                            r'([^a-zA-Z0-9]+)', password, re.M)
                        if specialMatch:
                            specChar = True
                        # Uppercase Character
                        ucMatch = re.search(r'([A-Z])', password, re.M)
                        if ucMatch:
                            ucChar = True
                        # Numeric Character
                        numMatch = re.search(r'([0-9])', password, re.M)
                        if numMatch:
                            numChar = True
                        # Create rules
                        if lenMin:
                            feature[0] = 1
                        if specChar and ucChar and numChar:
                            feature[1] = 3
                        if ucChar and numChar:
                            feature[2] = 1
                        if specChar and numChar:
                            feature[3] = 2
                        if specChar and ucChar:
                            feature[4] = 2
                        features.append(feature)
                        labels.append(int(label))
                        passwords.append(password)
            return [features,  labels, passwords]
        # Prepare the data
        trainingData = parseData(r'SupportVectorMachine\training.txt')
        testingData = parseData(r'SupportVectorMachine\test.txt')
        # A SVM Classifier
        clf = svm.SVC(kernel='linear', C=1.0)
        # Training the classifier with the passwords and their labels.
        clf = clf.fit(trainingData[0], trainingData[1])
        # Predicting a password Strength
        prediction = clf.predict(testingData[0])
        target = len(testingData[1])
        current = 0
        incorrect = 0
        SupportVectorMachine.clustering(1)
        for index in range(target):
            if(prediction[index] in [0, 1, 2]):
                flash(
                    "Insecure password according to LockBox Support Vector Classification.", "warning")
                return redirect('/login')
            elif(prediction[index] == 3):
                predicted = "Very Strong Password"

        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        password = hashlib.pbkdf2_hmac('sha256', request.form["password"].encode('utf-8'),
                                       salt, 100000)
        password = (salt + binascii.hexlify(password)).decode('ascii')
        # Aden: Retrieve the input/selected value for mobile phone and activation
        mobile = request.form["mobile"]
        activation = form.activation.data
        try:
            with shelve.open(DB_PATH, writeback=True) as db:
                db["login"][username] = {"password": password}
                # Aden: Appending the mobile phone and activation value into lockboxdb
                db["login"][username]["mobile"] = mobile
                db["login"][username]["activation"] = activation
        except Exception:
            flash("failed account creation", "warning")
            return redirect('/login')

        # josef: create user folder
        file_handler.new_dir(username)

        # Returns to login page
        flash('Your account has been registered', "success")
        return redirect('/login')
    return render_template('register.html', form=form)


# Aden: Login
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        # Get user form
        username = request.form["username"]
        password_candidate = request.form["password"]

        # image = request.form.get('submitPhoto')
        # status = lc(username, image)
        # print('Login status:', status)
        # if status == "Image not clear! Please try again!" or status == "Data does not exist!" or status == "Failed to Log in!":
        #     flash(status, "info")
        #     return render_template('login.html', form=form)

        try:
            with shelve.open(DB_PATH, "r") as db:
                data = db["login"][username]
        except KeyError:
            flash('Incorrect username or password entered', 'danger')
            return render_template('login.html', form=form)
        try:
            password = data["password"]
            """Verify a stored password against one provided by user"""
            salt = password[:64]
            password = password[64:]
            pwdhash = hashlib.pbkdf2_hmac('sha256', password_candidate.encode(
                'utf-8'), salt.encode('ascii'), 100000)
            pwdhash = binascii.hexlify(pwdhash).decode('ascii')
            # Compare password
            if pwdhash == password:
                try:
                    # Aden: Redirect users to 2FA if the password matches
                    activation = data["activation"]
                    if activation == "yes":
                        mobile = data["mobile"]
                        session["2fa_uname"] = username
                        verify.verifications.create(
                            to=f"+65{mobile}", channel='sms')
                        return redirect("/check2fa")

                    # Aden: Add the date and time when the user login
                    dt_string = dt.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                    session['logged_in'] = True
                    session['username'] = username
                    # Aden: Add datetime to shelve db
                    try:
                        with shelve.open(DB_PATH, writeback=True) as db:
                            db["login"][username]["Last Login Time"] = dt_string
                    except Exception:
                        flash("Failed login attempt", "danger")
                        return redirect('/login')

                    # Aden: Add in datetime in flash message
                    flash("Successful login. Login time: "+dt_string, "success")

                    # josef: create user folder
                    file_handler.new_dir(username)

                    return redirect("/files")
                except KeyError:
                    flash(
                        "Activation code not set. Please create a new account", "danger")
                    return render_template('login.html', form=form)
            else:
                flash('Incorrect username or password entered', 'danger')
                return render_template('login.html', form=form)
        except TypeError:
            flash('Incorrect username or password entered', 'danger')
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route("/files", methods=["GET", "POST"])
def files():
    if not user_logged_in():
        return redirect('/')
    if request.method == 'GET':

        # josef: get all files from user.
        dir = file_handler.files_in_dir(f"files/{session['username']}")

        return render_template('tables.html', files=dir)
    else:
        return redirect('/')


@app.route("/newfile", methods=['GET', 'POST'])
def new_file():
    if not user_logged_in():
        return redirect('/')
    elif request.method == 'GET':

        # josef: remove file password
        form = forms.File()

        return render_template('upload.html', form=form)
    elif request.method == 'POST':
        path = f"files/{session['username']}/"
        f = request.files['file']
        path += secure_filename(f.filename)
        f.save(path)
        if check_virus(path) == True:
            file_hash = hashlib.md5(open(path, 'rb').read()).hexdigest()
            d = shelve.open("database/virus.db")
            d[f.filename] = [file_hash]
            os.remove(path)
            flash("Virus detected. File has been deleted.", "danger")
            return redirect("/files")

        file_obj = file_handler.File(secure_filename(f.filename), path)
        # josef: remove file password encryption
        # key = str(request.form['key'])
        # file_obj.encrypt(key)

        # josef: upload file metadata
        FileMetadata.metadata_create(f.filename, session["username"])

        return redirect("/files")
    else:
        return redirect('/')


@app.route("/files/<filename>/download", methods=['GET', 'POST'])
def download_file(filename):
    if not user_logged_in():
        return redirect('/')
    elif request.method == 'GET':

        # josef: remove file password
        form = forms.File()

        return render_template('download.html', filename=filename, form=form)
    elif request.method == 'POST':

        # get file
        path = Path(f"files/{session['username']}/{filename}")
        # josef: remove file password encryption
        file_obj = file_handler.File(filename, path)

        # josef: remove file password encryption
        # # decrypt
        # key = str(request.form['key'])
        # file_obj.decrypt(key)

        # new_file_name = str(file_obj.name).replace('.aes', '')
        new_file_name = str(file_obj.name)

        # josef: remove the need for temp file path
        # new_file_path = 'files/temp'

        # if was successful in decrypting file
        if new_file_name in file_handler.files_in_dir(Path(f"files/{session['username']}")):

            # josef: remove the need for temp file path
            # new_file_path += new_file_name
            # # file_obj.remove()  # removes file from "file" directory.
            # new_file_obj = file_handler.File(new_file, new_file_path, None)
            # # with open(new_file_obj.path)

            return send_file(Path(path), as_attachment=True)
        else:
            return redirect("/files/" + filename + "/download")
    else:
        return redirect('/')


@app.route("/files/<filename>/delete", methods=['GET', 'POST'])
def delete_file(filename):
    if not user_logged_in():
        return redirect('/')
    elif request.method == 'GET':
        return render_template('delete.html', filename=filename)
    elif request.method == 'POST':
        path = Path(f"files/{session['username']}/{str(filename)}")
        file_obj = file_handler.File(filename, path)
        file_obj.remove()

        # josef: delete file metadata
        FileMetadata.metadata_del(filename, session["username"])

        return redirect("/files")
    else:
        return redirect('/')


# edwin: rich text editor
@app.route(f"/files/<filename>/modify")
def rich_edit(filename):
    if request.method == 'GET':
        if check_AFC_permission(filename) == False:
            abort(404)  # Mark
        logMe(filename,request.remote_addr,tempLogs,session['username']) # Mark
        newCode = AFCnewcode(filename, AFCDATA)  # Mark
        path = Path(f"files/{session['username']}/{filename}")
        with open(path) as t:
            text = t.read()
            if (text[:3]) == 'AES':
                istext = 2
                text = text[3:]
        return render_template('richedit.html', text=text, filename=filename, newcode=newCode)


# edwin: rich text editor
@app.route(f"/files/<filename>/update", methods=['GET', 'POST'])
def rich_submit(filename):
    if request.method == 'POST':
        path = Path(f"files/{session['username']}/{filename}")
        with open(path, "w") as myfile:
            newtext = request.form.get('updatedtext')
            myfile.write(newtext)
            flash(f"'{filename}' updated", "info")
            return redirect("/files")


# edwin: plain text editor
@app.route(f"/files/<filename>/cleanmodify")
def plain_edit(filename):
    if request.method == 'GET':
        if check_AFC_permission(filename) == False:
            abort(404)  # Mark
        logMe(filename,request.remote_addr,tempLogs,session['username']) # Mark
        newCode = AFCnewcode(filename, AFCDATA)  # Mark
        path = Path(f"files/{session['username']}/{filename}")
        with open(path) as t:
            text = t.read()
            if (text[:3]) == 'AES':
                istext = 2
                text = text[3:]
        return render_template('plainedit.html', text=text, filename=filename, newcode=newCode)


# edwin: plain text editor
@app.route(f"/files/<filename>/update", methods=['GET', 'POST'])
def plain_submit(filename):
    if request.method == 'POST':
        path = Path(f"files/{session['username']}/{filename}")
        with open(path, "w") as myfile:
            newtext = request.form.get('updatedtext')
            myfile.write(newtext)
            flash(f"'{filename}' updated", "info")
            return redirect("/files")


@app.route('/logout')
@app.route('/logout/')
def logout():
    session.pop('username', None)
    return redirect("/")


@app.errorhandler(404)
def page_not_found(e):
    # set 404 status explicitly
    return render_template('404.html'), 404

class SupportVectorMachine():
    def clustering(sec: int) -> None:
        time.sleep(1)
