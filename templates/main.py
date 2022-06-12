# logging
import logging
import logging.handlers
import os

# flask
from flask import Flask, escape, jsonify, request
from flask_cachebuster import CacheBuster
# JWT
from flask_jwt import JWT, current_identity, jwt_required
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
# Aden: CSRF Protection
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import safe_str_cmp

import user

DB_PATH="database/lockbox.db"
RECAPTCHA_PUBLIC_KEY="6LeQZSYeAAAAANGuQltFI26q-mdIUdhoGZLPDCwc"
RECAPTCHA_PRIVATE_KEY="6LeQZSYeAAAAAEPGfTSbBn2b1G00KXaOgQ1ACTh2"
TWILIO_ACCOUNT_SID="AC7e73146200053926ab75d83bdfbbeafb"
TWILIO_AUTHTOKEN="e9c6a1f600c9eaea61c5452a1afe0268"
TWILIO_VERIFY_SID="VAe0821662e595c3779995f4b3a98f7162"


def create_server():
    app = Flask(__name__)
    app.config.from_object('config.DevelopmentConfig')
    file_handler = logging.handlers.RotatingFileHandler('errorlog.txt')
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    return app


app = create_server()
from views import *  # NOTE: do NOT move this up!

app.secret_key = os.urandom(24)
# Aden: CSRF Protection
csrf = CSRFProtect(app)

#Mark's Stuff : place after 'app' is defined
from flask_socketio import SocketIO, emit
socketio = SocketIO(app)
from Mark_AFC import *




@socketio.event
def connect():
    print('Client connected')
    print(request.remote_addr)

@socketio.on('disconnect')
def test_disconnect():
    print(request.remote_addr)
    print('Client disconnected')
    starttime = tempLogs[request.remote_addr].get('start')
    endtime = datetime.now()
    sessionLength = (endtime-starttime).seconds
    file=tempLogs[request.remote_addr].get('file')
    country=tempLogs[request.remote_addr].get('country')
    username=tempLogs[request.remote_addr].get('username')
    username=tempLogs[request.remote_addr].get('username')
    time_accessed=starttime.strftime(format="%Y-%m-%dT%H:%M")
    path = f"files/LockBoard.log"
    file_object = open(path, 'a')
    file_object.write(str(file+'|'+time_accessed+'|'+str(sessionLength+1)+'|'+country+'|'+username+'\n'))
    file_object.close()
    print(tempLogs[request.remote_addr])
    tempLogs[request.remote_addr] = {}


def cache_buster():
    """ css cache buster """
    config = {'extensions': ['.js', '.css'], 'hash_size': 5}
    cache_buster = CacheBuster(config=config)
    cache_buster.init_app(app)


# run server
if __name__ == "__main__":
    print(" * starting --> lockbox\n")
    cache_buster()
    jwt = JWTManager(app)
    jwt = JWT(app, user.authenticate, user.identity)
    socketio.run(app,debug=app.config['DEBUG'], port=app.config['PORT'])
    app.run(debug=app.config['DEBUG'], port=app.config['PORT'])
