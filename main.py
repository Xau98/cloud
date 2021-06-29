import os
from flask import Flask, request, redirect, url_for, jsonify, current_app, send_from_directory, render_template
import werkzeug
from flask import send_file
import handle
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from flask import jsonify

app = Flask(__name__)

# ========================Test============================
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask import jsonify
from flask_sqlalchemy import SQLAlchemy

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt, get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)

ACCESS_EXPIRES = timedelta(hours=1)
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
jwt = JWTManager(app)

# We are using an in memory database here as an example. Make sure to use a
# database with persistent storage in production!
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# This could be expanded to fit the needs of your application. For example,
# it could track who revoked a JWT, when a token expires, notes for why a
# JWT was revoked, an endpoint to un-revoked a JWT, etc.
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)


# Callback function to check if a JWT exists in the database blocklist
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None


@app.route("/create", methods=["POST"])
def login():
    access_token = create_access_token(identity="example_user")
    return jsonify(access_token=access_token)


# Endpoint for revoking the current users access token. Saved the unique
# identifier (jti) for the JWT into our database.
@app.route("/delete", methods=["DELETE"])
@jwt_required()
def modify_token():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg="JWT revoked")


# A blocklisted access token will not be able to access this any more
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return jsonify(hello="world")


@app.route('/test2', methods=['GET'])
@jwt_required()
def upload_file2():
    jti = get_jwt()["jti"]
    print(jti)
    return "SERECT data "


@app.route('/test', methods=['POST'])
def upload_file():
    import jwt
    token = request.json.get('token')
    key = "super-secret"
    try:
        decode_token = jwt.decode(token, key, algorithms=['HS256'])
        print("Token is still valid and active" + str(decode_token))
        return "True"
    except jwt.ExpiredSignatureError:
        print("Token expired. Get new one")
        return "Account token expired "
    except jwt.InvalidTokenError:
        print("Invalid Token")
        return "Account token invalid"


@app.route('/demo', methods=['GET'])
def demo():
    return handle.executeScriptsFromFile('demo.sql')


# ==========================ACCOUNT============================

# INPUT : Thông tin đăng ký json {"name ,email, username, password, datecraete}
# OUTPUT : TRUE/FALSE
# FUNCITION : Hàm này dùng để đăng ký account
@app.route('/register', methods=['POST'])
def registerAccount():
    user = request.json
    return handle.register(user)


"""
Bkav Tiennvh: Xác thực sau khi đăng ký 
INPUT: 
        {
        "_id" : " ID account ",
        "code" : "mã code",
         “email”: “email” 
        }
OUTPUT:
        + Success :{
                    “result”: true
                    “objectData”:null 
                }   
        + False : {
                    “result”: false
                    “objectData”:  "<nguyên nhân gây lỗi >"
                }

"""


@app.route('/user/verify', methods=['POST'])
def verifyemail():
    user = request.json
    return handle.verifyEmailAndUpdate(user)


# INPUT : json{ id, token}
# OUTPUT : TRUE/FALSE
# FUNCITION : Hàm này dùng để đăng nhập account bằng token
@app.route('/logintoken', methods=['POST'])
def logintoken():
    acc = request.json
    return handle.logintoken(acc)


# INPUT :  json{username, password}
# OUTPUT : Trả về 1 Tkent
# FUNCITION : Hàm này dùng để đăng nhập băng account
@app.route('/loginaccount', methods=['POST'])
def loginAccount():
    if request.method == 'POST':
        # try:
        user = request.json
        return handle.login(user)
    # except:
    # return "False"


@app.route('/verifypassword', methods=['POST'])
def verifypassword():
    user = request.json
    return handle.verifyPassword(user)


@app.route('/logout', methods=['POST'])
def Logout():
    try:
        acc = request.json;
        handle.logOut(acc)
        return "True"
    except:
        return "False"


# ==================Upload File===============================
"""
if(pathsave=="false"):
            try:
                 # create name File
                 now = datetime.now()
                 # dd/mm/YY H:M:S"%S:%M:%H %d/%m/%Y"
                 dt_string = now.strftime("%Y%m%d_%H%M%S")
                 namefile ="Data"+dt_string
                 # create File
                 path = path0 + id
                 print(path)
                 os.mkdir(os.path.join(path, namefile))
                 path1 = path + "/"+ namefile
                 imagefile = request.files['uploaded_file']
                 filename = werkzeug.utils.secure_filename(imagefile.filename)
                 imagefile.save(os.path.join(path1,filename))
                 print (path1)
                 return path1
            except:
                print("file exit . error")
        else:
"""


@app.route('/uploadfile', methods=['POST'])
def handle_request():
    id = request.form.to_dict().get('id')
    pathsave = request.form.to_dict().get('pathsave')
    path0 = '/root/Bkav/Data/'
    verify = handle.verificationAccount(request.form.to_dict())
    if verify:
        try:
            path = os.path.join(path0, id)
            os.mkdir(path)
        except:
            print("folder exit")
        print(pathsave)
        try:

            path1 = os.path.join(path, pathsave)
            os.mkdir(path1)
        except:
            print("folder exit")

        imagefile = request.files['uploaded_file']
        filename = werkzeug.utils.secure_filename(imagefile.filename)
        path2 = path + "/" + pathsave
        imagefile.save(os.path.join(path2, filename))
        return filename
    return verify


@app.route('/download', methods=['POST'])
def downloadFile():
    # For windows you need to use drive name [ex: F:/Example.pdf]
    acc = request.json
    verifi = handle.verificationAccount(acc)
    if verifi:
        path = acc.get('path')
        print("Image download Successfully")
        return send_file(path, as_attachment=True)
    return verifi


@app.route('/removebackup', methods=['POST'])
def RemoveBackup():
    acc = request.json
    return handle.removeBackup(acc)


@app.route('/uploads/<path:filename>', methods=['POST'])
def download(filename):
    uploads = os.path.join(current_app.root_path, app.config['/Home'])
    return send_from_directory(directory=uploads, filename=filename)


# ====================Restore Backup========================

@app.route('/insertbackup', methods=['POST'])
def InsertBackup():
    try:
        acc = request.json
        handle.insertBackup(acc)
        return "True"
    except:
        return "False"


@app.route("/getlistbackup", methods=['POST'])
def GetListBackup():
    acc = request.json
    return handle.getListBackup(acc)


@app.route('/getbackuplast', methods=['POST'])
def GetBackupLast():
    try:
        acc = request.json
        return handle.backuplast(acc)
    except:
        return "chưa có lần backup nào "


# /root/Bkav/Data/3/Data20210424_083153
@app.route('/getlistdata', methods=['POST'])
def GetListData():
    acc = request.json
    return handle.getListData(acc)


@app.route('/renamebackup', methods=['POST'])
def RenameBackup():
    acc = request.json
    return handle.renameBackup(acc)


@app.route('/getListRestore', methods=['POST'])
def getListRestore():
    if request.method == 'POST':
        try:
            user = request.json
            return handle.getListRetore(user)
        except:
            return "FALSE"
    else:
        return "FALSE"


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    app.debug = True
    app.run(host="0.0.0.0", port=2406)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
