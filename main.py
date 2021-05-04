import os
from flask import Flask, request, redirect, url_for, jsonify, current_app, send_from_directory
import werkzeug
from flask import send_file
import bcrypt
from datetime import datetime
# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import handle

app = Flask(__name__)

#========================Test============================
@app.route('/test', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        user = request.json
        print(user)
        #print(user.get('tiennvh'))
        return "POST"
    else:
        path = os.path.join('/home/servercloud/Backup', 'test')
        os.mkdir(path)
        return "GET"
    return "NONO"
@app.route('/demo/<pass1>')
def demo(pass1):
    code = get_hashed_password(pass1)
    print(code)
    print('=============')
    print(check_password(pass1, code))
    return code


#==========================login============================
# plain_text_password ; string
def get_hashed_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    return bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt( 12 ))

def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password)


#INPUT : Thông tin đăng ký json {"name ,email, username, password, datecraete}
#OUTPUT : TRUE/FALSE
# FUNCITION : Hàm này dùng để đăng ký account
@app.route('/register', methods=['GET', 'POST'])
def registerAccount():
    if request.method == 'POST':
        user = request.json
        return  handle.register(user)
    else:
         return "False"
    return "True"

#INPUT : json{ id, token}
#OUTPUT : TRUE/FALSE
# FUNCITION : Hàm này dùng để đăng nhập account bằng token
@app.route('/logintoken', methods=['GET', 'POST'])
def logintoken():
    try:
     if request.method == 'POST':
         user = request.json
         result= handle.logintokent(user)
    except:
        return "Error 404 : "
    return result

#INPUT :  json{username, password}
#OUTPUT : Trả về 1 Tkent
# FUNCITION : Hàm này dùng để đăng nhập băng account
@app.route('/loginaccount', methods=['GET', 'POST'])
def loginAccount():
    if request.method == 'POST':
        try:
            user = request.json
            return handle.loginaccount(user)
        except:
           return "False"
    return "False"


@app.route('/logout', methods=['GET', 'POST'])
def Logout():
    try:
          acc = request.json;
          handle.logOut(acc)
          return "True"
    except:
           return "False"
#==================Upload File===============================
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
@app.route('/uploadfile', methods = ['GET', 'POST'])
def handle_request():
    id = request.form.to_dict().get('id')
    pathsave = request.form.to_dict().get('pathsave')
    path0 ='/root/Bkav/Data/'
    if(handle.verificationAccount(request.form.to_dict())):
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
        path2 = path+"/"+pathsave
        imagefile.save(os.path.join(path2,filename))

        return path2
    return "False"


@app.route('/download', methods=['GET', 'POST'])
def downloadFile ():
    #For windows you need to use drive name [ex: F:/Example.pdf]
    acc = request.json
    handle.verificationAccount(acc)
    path = acc.get('path')
    print("Image download Successfully")
    return send_file(path, as_attachment=True)

@app.route('/removebackup', methods=['GET', 'POST'])
def RemoveBackup():
    acc = request.json
    return handle.removeBackup(acc)


@app.route('/uploads/<path:filename>', methods=['GET', 'POST'])
def download(filename):
    uploads = os.path.join(current_app.root_path, app.config['/Home'])
    return send_from_directory(directory=uploads, filename=filename)
#====================Restore Backup========================

@app.route('/insertbackup', methods=['GET', 'POST'])
def InsertBackup():
    try:
        acc = request.json
        handle.insertBackup(acc)
        return "True"
    except:
           return "False"

@app.route("/getlistbackup", methods = ['GET', 'POST'])
def GetListBackup():
    acc = request.json
    return handle.getListBackup(acc)

@app.route('/getbackuplast', methods=['GET', 'POST'])
def GetBackupLast():
    try:
        acc = request.json
        return handle.backuplast(acc)
    except:
        return "chưa có lần backup nào "

#/root/Bkav/Data/3/Data20210424_083153
@app.route('/getlistdata', methods =['GET', 'POST'])
def GetListData():
    acc = request.json
    return handle.getListData(acc)

@app.route('/renamebackup', methods=['GET', 'POST'] )
def RenameBackup():
    acc = request.json
    return handle.renameBackup(acc)



@app.route('/getListRestore', methods=['GET', 'POST'])
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
    app.debug= True
    app.run(host="0.0.0.0", port=2405)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
