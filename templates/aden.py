import binascii
import datetime
import hashlib
import json
import os
import shelve
import time as Support_Vector
from pathlib import Path
import time

from dotenv import load_dotenv
from flask import (abort, flash, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from flask_jwt import JWT, current_identity, jwt_required
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
from twilio.rest import Client  # Aden
from werkzeug.utils import secure_filename
from werkzeug.wrappers import response

import file_handler
from forms import Form2fa, LoginForm, RegisterForm  # Aden
from main import app

load_dotenv()
DB_PATH = os.getenv("DB_PATH")


# Aden: Implement Twilio 2fa
# client format: Client("<account SID>", "<auth token>")
client = Client(os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTHTOKEN"))
verify = client.verify.services(os.getenv("TWILIO_VERIFY_SID"))


# Aden: Checking 2FA
@app.route("/check2fa", methods=['GET', 'POST'])
def check2fa():
    form = Form2fa(request.form)
    # form_login = RegisterForm(request.form)
    username = session["2fa_uname"]
    if request.method == 'POST' and form.validate():
        # Retrieve OTP from 2FA Form
        code2fa = form.code2fa.data
        # try:
        print(f"\n{username}\n")
        with shelve.open(DB_PATH, "r") as db:
            data = db["login"][username]
        # except Exception as e:
        #     flash(f"An error has occurred {e}", "danger")
        #     return redirect('/login')

        # Retrieve Mobile number from Register Form
        mobile = data["mobile"]
        result = verify.verification_checks.create(
            to=f"+65{mobile}", code=code2fa)
        if result.status == "approved":
            session['logged_in'] = True
            session['username'] = username
            # Aden: Add the date and time when the user login
            dt_string = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            # Aden: Add datetime to shelve db
            try:
                with shelve.open(DB_PATH, writeback=True) as db:
                    db["login"][username]["Last Login Time"] = dt_string
            except Exception:
                flash("Failed login attempt", "danger")
                return redirect('/login')

            # Aden: Add in datetime in flash message
            flash("Successful login. Login time: "+dt_string, "success")
            return redirect('/files')
        elif result.status == "pending":
            flash("Unsuccessful 2FA", "danger")
        #         return redirect('/login')
        # except Exception as e:
        #     flash(f"An error has occurred {e}", "danger")
            return redirect('/login')
    return render_template('check2fa.html', form=form)
