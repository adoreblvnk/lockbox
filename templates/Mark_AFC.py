from flask import Flask, Response, render_template, request, redirect, url_for, make_response
from datetime import datetime
import sys
from threading import Thread
import time
import base64
import os
from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont
from pathlib import Path
import pyAesCrypt
from main import app #requires this in order to run 'app' as declared in main.py
from flask import (abort, flash, jsonify, redirect, render_template, request,send_file, session) #requires this to access session attrs
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

#overwrite the heroforce file
with open('./files/peter/heroforce.txt', "w") as myfile:
    newData='''HeroForce.com is a fictional organization that recruits and trains superheroes. Each year, we organise a 12-hour long recruitment event open to all students in Singapore.
Participants have to overcome a series of challenges by existing members of HeroForce.com.
Besides strong technical skills, potential superheroes will also need to display creativity, resourcefulness, and above all, teamwork. Are you ready to become a member of HeroForce?
'''
    myfile.write(newData)
global tempLogs
tempLogs = {}


def user_logged_in():
    return 'username' in session

class AESCipher(object):
# credit to https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def newencrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encryptedOutput = 'AES'+(base64.b64encode(iv)).decode('utf-8')+'||'+(base64.b64encode(cipher.encrypt(raw.encode()))).decode('utf-8')
        return encryptedOutput

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encryptedOutput = ''+(base64.b64encode(iv + cipher.encrypt(raw.encode()))).decode('utf-8')
        return encryptedOutput

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

AFC_TEMPLATE_DIR = './'

AFCDATA = {}

def watermark_text(input_image_path,output_image_path,text):
    photo = Image.open(input_image_path)
    # make the image editable
    drawing = ImageDraw.Draw(photo)
    black = (3, 8, 12)

    fontsize =1
    img_fraction = 0.80
    font = ImageFont.truetype("arial.ttf", fontsize)
    while font.getsize(text)[0] < img_fraction*photo.size[0]:
    # iterate until the text size is just larger than the criteria
        fontsize += 1

        font = ImageFont.truetype("arial.ttf", fontsize)
    pos=(30,(photo.size[0]/3))
    drawing.text(pos, text, fill=black, font=font)
    #photo.show() #displays the image in photo viewer
    photo.save(output_image_path)

def isOwner(filename,username):
    return True

def check_AFC_permission(filename):
    check = False
    try:
        attributeDict = AFCDATA[filename]
    except:
        return True
    timenow = datetime.now()
    if attributeDict['delafter']:
        if timenow > attributeDict['delafter']:
            check=False
            return False
    if isinstance(attributeDict['maxviews'],int):
        if attributeDict['maxviews'] == 0:
            check=False
            return False
        attributeDict['maxviews']-= 1
    return True

def getAFCattributesCheckbox(filename,AFCDATAdict):
    output = ['','','','','','']
    try:
        attributeDict = AFCDATAdict.get(filename)
        n = 0
        for key in attributeDict:
            if attributeDict.get(key) != None:
                output[n] = 'checked'
                if n==0:
                    output[n] = 'checked disabled'
                    output[-1] = "style='display:none;'"
            n += 1
            #print(output)
        return output
    except:
        return output

def getAFCattributesFields(filename,AFCDATAdict):
    baselist = ["","60","2022-01-27T16:30",1,"Watermark Text Goes Here"]
    try:
        attributeDict = AFCDATAdict.get(filename)
        n = 0
        for key in attributeDict:
            if attributeDict.get(key) != None:
                baselist[n] = attributeDict.get(key)
            n += 1
        if baselist[3] == 0:
            baselist[3]=1
        baselist[2] = (baselist[2]).strftime('%Y-%m-%dT%H:%M')
        return baselist
    except:
        return baselist

def AFCnewcode(filename,AFCDATAdict):
    output='''<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js" integrity="sha512-bLT0Qm9VnAYZDflyKcBaQ2gg0hSYNQrJ8RilYldYQ1FxQYoCLtUjuuRuZo+fjqhx/qtq/1itJ0C2ejDxltZVFg==" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/3.0.4/socket.io.js" integrity="sha512-aMGMvNYu8Ue4G+fHa359jcPb1u+ytAF+P2SCb+PxrjCdO3n3ZTxJ30zuH39rimUggmTwmh2u7wvQsDTHESnmfQ==" crossorigin="anonymous"></script>
      <script id="socketio-logger">
$(document).ready(function() {
            // Connect to the Socket.IO server.
            // The connection URL has the following format, relative to the current page:
            //     http[s]://<domain>:<port>[/<namespace>]
            var socket = io();

            // Event handler for new connections.
            // The callback function is invoked when a connection with the
            // server is established.
            socket.on('connect', function() {
                console.log('connected to server');
            });})

      </script>'''
    SESSIONMODAL = '''<div class="modal fade" id="timeoutModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="exampleModalLabel" style="color:black;">Time's nearly up!</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body" style="color:black;">
        Would you like to extend your session?
      </div>
              <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal" onclick="userExtendSession()">Yes</button>
        <button type="button" class="btn btn-secondary" onclick="userEndSession();">No</button>
      </div>
    </div>
  </div>
</div>
        <script>
        var timeouttime = (&&&time&&&*1000)/2;
       //var socket = io();
var EndSession = null;
var ShowModal = setTimeout(function(){$('#timeoutModal').modal('show');EndSession = setTimeout(userEndSession, timeouttime+500);}, timeouttime);


function userEndSession() {
  window.location.replace("/logout");
  //socket.emit('userEndSession');
}

function userExtendSession() {
clearTimeout(EndSession);
var ShowModal = setTimeout(function(){$('#timeoutModal').modal('show');EndSession = setTimeout(userEndSession, timeouttime+500);}, timeouttime);

}</script>'''
    AESDECRYPTER = '''<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/aes.js"></script>
        <script>
function DoDecrypt() {
async function hash(string) {
  const utf8 = new TextEncoder().encode(string);
  const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((bytes) => bytes.toString(16).padStart(2, '0'))
    .join('');
  return hashHex;
}
var key = prompt("Enter password to decrypt file");
try {
  var RAWFILEDATA=document.getElementById('textDisplay').innerHTML;
} catch (error) {
 var RAWFILEDATA=document.getElementById('open-source-plugins_ifr').contentWindow.document.getElementById('tinymce').textContent;
};

var fileiv = RAWFILEDATA.split('||')[0];
var filedata = RAWFILEDATA.split('||')[1];
var pwhash = '';
var decrypted = '';
var plaintext = ''
hash(key).then((hex) => pwhash = hex);

function decryptASYNC(tt) {

var key = CryptoJS.enc.Hex.parse(tt);
console.log(tt);
console.log(key);
var iv = CryptoJS.enc.Base64.parse(fileiv);

decrypted = CryptoJS.AES.decrypt(filedata, key, { iv: iv });
console.log(decrypted);
plaintext = decrypted.toString(CryptoJS.enc.Utf8);
console.log(plaintext);
if (plaintext == '') {
  plaintext='Decryption Failed.';
}
try {
  document.getElementById('textDisplay').textContent=plaintext;
} catch (error) {
document.getElementById('open-source-plugins_ifr').contentWindow.document.getElementById('tinymce').textContent=plaintext;
};

try {

document.getElementById("imageDisplay").src = "data:image/png;base64, ".concat(plaintext);
} catch (error) {
  console.error('not an image');
};
return plaintext;
};

setTimeout(function() {
    decryptASYNC(pwhash);
}, 1000);
}
const myTimeout = setTimeout(DoDecrypt, 500);
        </script>'''
    if AFCDATAdict == 0: # for external loads
        AFCDATAdict = AFCDATA
    try:
        attributeDict = AFCDATAdict.get(filename)
        print("AFCNEWCODE",attributeDict,file=sys.stdout)
        if isinstance(attributeDict['maximum'],int):
            newmodal = SESSIONMODAL.replace("&&&time&&&",str(attributeDict['maximum']))
            output += newmodal
        if isinstance(attributeDict['encrypt'],str):
            output += AESDECRYPTER
    except:
        return output
        pass
    return output

def HandleWatermark(filename,path,initial):
    try:
        watermarkText = AFCDATA.get(filename).get('watermark')
        test1 = watermarkText[1]
    except:
        return initial
    TEMPFILE = 'newimage2.png'
    watermark_text(str(path), "./templates/Mark_AFC_templates/watermarktemp.png" ,text=watermarkText)
    with open("./templates/Mark_AFC_templates/watermarktemp.png", "rb") as img_file:
        b64_string = base64.b64encode(img_file.read())
    output=str(b64_string)[2:-1]
    os.remove("./templates/Mark_AFC_templates/watermarktemp.png")
    return output

def HandleEncryption(path,key):
    addon=".AES"
    addon='' # OVERWRITES EXISTING FILE!!!!
    try:
        f = open(str(path), "r") #assume text file
        input = f.read()
        f.close()
        if 'AES' in input: #prevent double encryption
            return False
    except: #b64 binary file
        with open(path, "rb") as img_file:
            result = img_file.read()
            b64_string = base64.b64encode(result)
            input=str(b64_string)[2:-1]
            print(input)
            if 'AES' in input[:7]: #prevent double encryption
                return False
    input=HandleWatermark(path.split('/')[-1],path,input)
    cipher = AESCipher(key)
    output = cipher.newencrypt(input)
    f = open(str(str(path)+addon), "w")
    f.write(output)
    f.close()
    print(str(str(path) + "Encrypted"))
    #os.remove("./templates/Mark_AFC_templates/watermarktemp.png")
    return

@app.route('/Mark_AFC_admin/<filename>', methods=['GET','POST'])
def AFCadmin(filename):
    if not user_logged_in():
        return redirect('/')
    ErrorMessage = 'Error in form data'
    if isOwner(filename,session['username']) == False: abort(404) #Mark
    if request.method == 'GET':
        path = Path(f"files/{session['username']}/{filename}")
        istext=1
        try:
            with open(path) as t:
                text = t.read()
                if (text[:3]) == 'AES':
                    istext=2
                    text=text[3:]

        except:
            with open(path, "rb") as img_file:
                result = img_file.read()
                b64_string = base64.b64encode(result)
                text=str(b64_string)[2:-1]
                text=HandleWatermark(filename,path,text)
                istext=3
        #print(text)

        if text[:5]=='QUVTS':
            text=base64.b64decode(text)
            #print(text)
        if str(path)[-3:]!='txt': #not text means image
            print('Encrypted Image')
            istext=3
        checkbox = getAFCattributesCheckbox(filename,AFCDATA)
        fields = getAFCattributesFields(filename,AFCDATA)
        print(checkbox,fields)
        newcode = AFCnewcode(filename,AFCDATA)
        logMe(filename,request.remote_addr,tempLogs,session['username'])
        return render_template('Mark_AFC_templates/admin.html', text=text, filename=filename,CheckboxValues=checkbox,fileAFCData=fields,istext=istext,filepath=path,newcode=newcode)
    elif request.method == 'POST':
        workdict={'encrypt':None,'maximum':None,'delafter':None,'maxviews':None,'watermark':None}
        print(request.form.keys())
        try:
            if request.form.get('encrypt?') == '1':
                encryptKey = request.form.get('encrypt')
                if not str(encryptKey):
                    ErrorMessage='No Encryption Key supplied'
                    raise ValueError
                path1 = str(Path(f"files/{session['username']}/{filename}"))
                print('Encrypt file//' + encryptKey, path1,file=sys.stderr)
                if encryptKey != '********':
                    HandleEncryption(path1,encryptKey)
                print("File Encrypted")
                workdict['encrypt'] = "********"
            if request.form.get('encrypt') == '********': #persist encrypted state
                workdict['encrypt'] = "********"
            if request.form.get('maximum?') == '1':
                maximum = int(request.form.get('maximum'))
                #print('maximum//',maximum, file=sys.stderr)
                workdict['maximum'] = maximum

            if request.form.get('delafter?') == '1':
                delafter = datetime.strptime(request.form.get('delafter'),'%Y-%m-%dT%H:%M')
                print('delafter//',delafter, file=sys.stderr)
                workdict['delafter'] = delafter

            if request.form.get('maxviews?') == '1':
                maxviews = int(request.form.get('maxviews'))
                workdict['maxviews'] = maxviews
                #print('maximum//',maxviews, file=sys.stderr)

            if request.form.get('watermark?') == '1':
                watermark = request.form.get('watermark')
                #print('maximum//',watermark, file=sys.stderr)
                workdict['watermark'] = watermark

            #print('CHECKED',file=sys.stdout)
            AFCDATA[filename] = workdict
            flash('Changes to AFC updated', 'success')
            return redirect("/files")
        except:
            return redirect(url_for("AFCadmin",filename=filename))

@app.route('/bigadmin', methods=['GET','POST'])
def bigadmin():
    if not user_logged_in():
        return redirect('/')

    if request.method == 'GET':
        user = session['username']
        import file_handler
        dir = file_handler.files_in_dir(f"files/{session['username']}")
        print(dir)
        public = []
        internal = []
        private = []
        custom = []
        for i in dir:
            try:
                attributeDict = AFCDATA.get(i)
                print(attributeDict)
                print(AFCDATA)
                if attributeDict['maximum'] == "120":
                    private.append(i)
                elif attributeDict['watermark'] == "Internal Data. Do not share.":
                    internal.append(i)
                elif attributeDict['delafter'] != None:
                    public.append(i)
            except:
                custom.append(i)
        return render_template('Mark_AFC_templates/bigadmin.html',public=public,internal=internal,private=private,custom=custom)
    elif request.method == 'POST':
        workdict={'encrypt':None,'maximum':None,'delafter':None,'maxviews':None,'watermark':None}
        print(request.form.keys())
        try:
            print(1)
        except:
            return redirect(url_for("AFCadmin",filename=filename))

#====================================
# LockBoard Details
#====================================

LOGDATA = {}

def ipInfo(addr):
    from urllib.request import urlopen
    from json import load
    url = 'https://ipinfo.io/' + addr + '/json'
    res = urlopen(url)
    #response from url(if res==None then check connection)
    data = load(res)
    #will load the json response into data
    print(data)
    #return data["country"] removed until public ip obtained
    return "Singapore"

def logMe(file,ip,tempdir,username='UNKNOWN USER'):
    country=ipInfo(ip)
    time_accessed1 = datetime.now()
    time_accessed=time_accessed1.strftime(format="%Y-%m-%dT%H:%M")
    print(time_accessed)

    # path = f"files/LockBoard.log"
    # file_object = open(path, 'a')
    # file_object.write(str(file+'|'+time_accessed+'|'+country+'|'+username+'\n'))
    # file_object.close()
    tempdir[ip] = {'file':file,
                  'start':time_accessed1,
                   'country':country,
                   'username':username}

@app.route('/Mark_LockBoard/<filename>', methods=['GET'])
def LockBoard(filename):
    if not user_logged_in():
        return redirect('/')
    if request.method=='GET':
        path = Path(f"files/{session['username']}/{filename}")
        file1 = open('files/LockBoard.log', 'r')
        logs = []
        Lines = file1.readlines()
        countryValues={}
        MapJsVars = ''
        baseCountryJSString = '"France": 5,'
        for line in Lines:
            array = line.split('|')
            if array[0] == filename:
                logs.insert(0,array)
                if array[2] not in countryValues:
                    countryValues[array[2]]=1
                else:
                    countryValues[array[2]] = countryValues[array[2]] + 1
        for i in countryValues.keys():
            MapJsVars += f'"{i}": {countryValues.get(i)},'
        views = len(logs)
        return render_template('Mark_AFC_templates/lockboard.html', filename=filename,MapJsVars=MapJsVars,logs=logs[:20],views=views)



