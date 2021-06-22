from sqlite3 import OperationalError

import mysql.connector
import jwt
import re
import json
import bcrypt
import os
import uuid
import random
from datetime import datetime
from flask import render_template
import shutil

# value return
ERROR_EMPTY = "Empty"  # Kết quả trả về rỗng (client gửi data lên thiếu dữ liệu )
RETURN_NONE = "Wrong name Params"
RETURN_TRUE = "True"  # Kết quả trả về là True
RETURN_FALSE = "False"
RETURN_STANDARD = "Email or Number phone Not Standard"
RETURN_PASSWORD_NOT_SAFE = "Password not safe"
RETURN_PASSWORD_WRONG = "Password wrong"
RETURN_INVALID_EMAIL = "Invalid email address"
RETURN_SEND_EMAIL = "Send code email error"
RETURN_USER_EXIT = "User exist"
RETURN_USER_NOT_EXIT = "User not exist "
# Response code
CODE_SUCCESS = 200
CODE_EMPTY = 1001
CODE_NULL = 1005
CODE_INVALID_EMAIL = 1110
CODE_PASSWORD_NOT_SAFE = 1112
CODE_PASSWORD_WRONG = 1115
CODE_SEND_EMAIL = 1100
CODE_USER_EXIT = 1106
CODE_USER_NOT_EXIT = 1105
# TIMEOUT
TIME_VERYCODE = 30 * 60  # Thời gian sống của mã code là 30p
TIME_TOKEN = 30 * 24 * 60 * 60  # Thời gian sống của token là 30 day
# NAME TABLE
TABLE_ACCOUNT = "databaseIOT.account"
TABLE_SAVE_CODE = "databaseIOT.save_code_verify"
TABLE_SAVE_TOKEN = "databaseIOT.save_token"
# PARAGRAM
ID_ACCOUNT = "_id"
USERNAME = "username"
PASSWORD = "password"
EMAIL = "email"
TOKEN = "token"
# QUERY
LIMIT_QUERY = 1  # Giới hạn kết quả trả về của SQL
SELECT_ACCOUNT_BY_USERNAME = "select * from " + TABLE_ACCOUNT + \
                             " where username = %s && is_active = %s limit %s"

SELECT_ACCOUNT_BY_ID_ACCOUNT = "select username_account_IOT,password_account_IOT," \
                               "name_company_account_IOT,level_account_IOT,timeout_account_IOT" \
                               " from  " + TABLE_ACCOUNT + \
                               "  where id_account_IOT = %s && is_active_account_IOT = %s limit %s"

UPDATE_PASSWORD_ACCOUNT = "update " + TABLE_ACCOUNT + \
                          " set password_account_IOT = %s  where id_account_IOT = %s limit %s"

SELECT_CODE_BY_ID_ACCOUNT = "select id_save_code_verify from " + TABLE_SAVE_CODE + \
                            " where id_account = %s && username = %s limit %s"
UPDATE_CODE_BY_ID_ACCOUNT = "update " + TABLE_SAVE_CODE + " set code_verify = %s ,  date_create = %s " \
                                                          "where id_account = %s limit %s"
INSERT_CODE = "INSERT INTO " + TABLE_SAVE_CODE + " (id_account, username, code_verify, date_create)" \
                                                 " VALUES (%s, %s, %s, %s)"

INSERT_TOKEN_BY_ID_ACCOUNT = "INSERT INTO " + TABLE_SAVE_TOKEN + " (id_account, time_login, token) " \
                                                                 "VALUES (%s, %s, %s)"

mydb = mysql.connector.connect(
    host="localhost",
    user="servercloud",
    password="123456a@A",
    auth_plugin='mysql_native_password'
)


# =========================test======================

def executeScriptsFromFile(filename):
    # Open and read the file as a single buffer
    fd = open(filename, 'r')
    sqlFile = fd.read()
    fd.close()

    # all SQL commands (split on ';')
    sqlCommands = sqlFile.split(';')

    # Execute every command from the input file
    for command in sqlCommands:
        # This will skip and report errors
        # For example, if the tables do not yet exist, this will skip over
        # the DROP TABLE commands
        try:
            cur = mydb.cursor()
            cur.execute(command)
        except OperationalError as msg:
            print("Command skipped: ", msg)
        print(command)
    return "FALSE"


# =============================================

# user = "root",
# password = "Tiennvh98@"

def register(user):
    name = user.get('name')
    email = user.get('email')
    username = user.get('username')
    password = user.get('password')
    time_now = datetime.now().timestamp()

    if username is None or name is None or password is None or email is None:
        return convertJSON(CODE_NULL, False, RETURN_NONE)
    # Bkav Tiennvh: Check thông tin rỗng
    if not username or not name or not password or not email:
        return convertJSON(CODE_EMPTY, False, ERROR_EMPTY)
    # Bkav Tiennvh:check format
    if not checkStandard(password, PASSWORD):
        return convertJSON(CODE_PASSWORD_NOT_SAFE, False, RETURN_PASSWORD_NOT_SAFE)
    if not checkStandard(email, EMAIL):
        return convertJSON(CODE_INVALID_EMAIL, False, RETURN_INVALID_EMAIL)

    sql_login = "select * from databaseIOT.account where username = %s limit %s"
    val_login = (username, LIMIT_QUERY)
    cur = mydb.cursor()
    isExit = 0
    password_hash = get_hashed_password(password)
    cur.execute(sql_login, val_login)
    for record in cur.fetchall():
        is_active = record[7]
        if is_active == 1:
            return convertJSON(CODE_USER_EXIT, False, RETURN_USER_EXIT)
        isExit = record[0]
        sql_register0 = "update " + TABLE_ACCOUNT + \
                        " set name_account= %s, email_account= %s, username= %s , password= %s , date_create =%s" \
                        " where id_account = %s limit %s"
        val_register0 = (name, email, username, password_hash, time_now, isExit, LIMIT_QUERY)
        insert(sql_register0, val_register0)

    # Bkav Tiennvh: Chưa tồn tại thì insert
    if isExit == 0:
        isExit = str(uuid.uuid1())
        sql_register = "INSERT INTO " + TABLE_ACCOUNT + \
                       "(id_account, name_account, email_account, username, password, date_create )" \
                       "VALUES (%s, %s, %s, %s, %s, %s) "
        val_register = (isExit, name, email, username, password_hash, time_now)
        insert(sql_register, val_register)

    data_token = {ID_ACCOUNT: isExit,
                  USERNAME: username,
                  'email': email,
                  'name': name,
                  'date_create': time_now}
    # Bkav Tiennvh: create token
    token = jwt.encode(data_token, password_hash, algorithm='HS256')
    account = {
        ID_ACCOUNT: isExit,
        EMAIL: username,
        TOKEN: token
    }
    code = random.randint(100000, 999999)
    # Bkav Tiennvh: send code cho email
    if send_email(username, code):
        # insert token and active
        val_check = (isExit, username, LIMIT_QUERY)
        cur1 = mydb.cursor()
        cur1.execute(SELECT_CODE_BY_ID_ACCOUNT, val_check)
        # Bkav Tiennvh: Check Account đã tồn tại nhưng chưa được kích hoạt
        if len(cur1.fetchall()) != 0:
            # Bkav Tiennvh:Nếu có rồi thì update
            val_code = (code, time_now, isExit, LIMIT_QUERY)
            updateDB(UPDATE_CODE_BY_ID_ACCOUNT, val_code)
            return convertJSON(CODE_SUCCESS, True, account)
        # Bkav Tiennvh:Nếu chưa thì tạo mới
        val_code = (isExit, username, code, time_now)
        insert(INSERT_CODE, val_code)
        return convertJSON(CODE_SUCCESS, True, account)
    return convertJSON(CODE_SEND_EMAIL, False, RETURN_SEND_EMAIL)


def verifyEmailAndUpdate(user):
    id = user.get(ID_ACCOUNT)
    username = user.get(EMAIL)
    type = user.get('type')
    if id is None or username is None:
        return convertJSON(CODE_NULL, False, RETURN_NONE)
    # Bkav Tiennvh:Check rỗng
    if not id or not username:
        return convertJSON(CODE_EMPTY, False, ERROR_EMPTY)
    if not checkStandard(username, EMAIL):
        return convertJSON(CODE_INVALID_EMAIL, False, RETURN_INVALID_EMAIL)
    # TODO number phone
    sql_update = None
    # Bkav Tiennvh: Phân loại mục đích của API
    if type == 'signup':
        sql_update = "update " + TABLE_ACCOUNT + " set is_active = %s where id_account = %s limit %s"
        val_update = (True, id, LIMIT_QUERY)
    if type == 'updateemail':
        sql_update = "update " + TABLE_ACCOUNT + " set username = %s where id_account = %s limit %s"
        val_update = (username, id, LIMIT_QUERY)
    # Bkav Tiennvh:Xác tực Account
    print("test")
    result_check_account = verificationAccount(user)
    if result_check_account == RETURN_TRUE:
        # Bkav Tiennvh:Xác thực mã code
        result_check_code = checkCodeVerify(user)
        if result_check_code == RETURN_TRUE:
            # Bkav Tiennvh:Cập nhật data sau khi xác thực
            if sql_update is not None:
                print(sql_update)
                updateDB(sql_update, val_update)
            return convertJSON(CODE_SUCCESS, True, None)
        return result_check_code
    return result_check_account


def login(user):
    username = user.get(USERNAME)
    password = user.get(PASSWORD)
    time_now = datetime.now().timestamp()
    # Bkav Tiennvh: Check none
    if username is None or password is None:
        return convertJSON(CODE_NULL, False, RETURN_NONE)
    # Bkav Tiennvh: Check rỗng
    if not username or not password:
        return convertJSON(CODE_EMPTY, False, ERROR_EMPTY)
    # Bkav Tiennvh:Check format
    if not checkStandard(password, PASSWORD):
        return convertJSON(CODE_PASSWORD_NOT_SAFE, False, RETURN_PASSWORD_NOT_SAFE)
    if not checkStandard(username, EMAIL):
        return convertJSON(CODE_INVALID_EMAIL, False, RETURN_INVALID_EMAIL)

    val_login = (username, True, LIMIT_QUERY)
    cur = mydb.cursor()
    cur.execute(SELECT_ACCOUNT_BY_USERNAME, val_login)
    # Bkav Tiennvh:Check account
    for record in cur.fetchall():
        id = record[0]
        key = record[4]
        timeout = 60 * 60 * 24 * 2
        # Bkav Tiennvh: Check password
        # TODO : xem return cua check password
        if not check_password(password, key):
            return convertJSON(CODE_PASSWORD_WRONG, False, RETURN_PASSWORD_WRONG)
        data_token = {ID_ACCOUNT: id, "name": record[1], USERNAME: record[3], 'email': record[2],
                      'exp': time_now + timeout}

        # Bkav Tiennvh:Tạo token
        token = jwt.encode(data_token, key, algorithm='HS256')
        # insert token and active

        account = {
            ID_ACCOUNT: id,
            "name": record[1],
            USERNAME: record[3],
            'email': record[2],
            TOKEN: token,
            "date_create": record[6]
        }
        return convertJSON(CODE_SUCCESS, True, account)

    return convertJSON(CODE_USER_NOT_EXIT, False, RETURN_USER_NOT_EXIT)


def logOut(acc):
    id = acc.get('id')
    verifi = verificationAccount(acc)
    if verifi:
        sql_token = "update databaseIOT.account set token = %s  where id_account= %s limit 1"
        val_token = (0, id)
        updateDB(sql_token, val_token)
    return verifi


# =======================Backup======================================


def insertBackup(acc):
    id = acc.get('id')
    namebackup = acc.get('namebackup')
    namedevice = acc.get("namedevice")
    path = acc.get("path")
    verifi = verificationAccount(acc)
    if verifi:
        sql_insert = "INSERT INTO databaseIOT.history_backup (name_history, date_backup, devices_backup, id_account, path_backup)" \
                     " VALUES (%s, %s, %s, %s, %s)"
        val_insert = (namebackup, getTimeNow(), namedevice, id, path)
        updateDB(sql_insert, val_insert)
    return verifi


def removeBackup(acc):
    path = acc.get('pathsave')
    nameFolder = acc.get('namefolder')
    id_history = acc.get('id_history')
    print(path, nameFolder)
    verifi = verificationAccount(acc)
    if verifi:

        dir_path = path + "/" + nameFolder
        try:
            shutil.rmtree(dir_path)
        except OSError as e:
            print("Error: %s : %s" % (dir_path, e.strerror))

        # update mysql
        sql = "DELETE FROM databaseIOT.history_backup WHERE id_history =%s limit %s"
        val = (id_history, 1)
        cur = mydb.cursor()
        cur.execute(sql, val)
        mydb.commit()
        return "True"
    return verifi


def getListBackup(acc):
    id = acc.get('id')
    verify = verificationAccount(acc)
    if verify:
        sql = "select *  from databaseIOT.history_backup where id_account = %s limit %s"
        val = (id, 100)
        cur = mydb.cursor()
        cur.execute(sql, val)
        alist = []
        for record in cur.fetchall():
            account = {
                "id_history": record[0],
                "name_history": record[1],
                "date_backup": record[2],
                "devices_backup": record[3],
                "pathsave": record[5]
            }
            print(account)
            alist.append(account)
        data_set = {"content": alist}
        return json.dumps(data_set)
    return verify


def backuplast(acc):
    id = acc.get('id')
    verify = verificationAccount(acc)
    if verify:
        sql_backup = "select date_backup from databaseIOT.history_backup where id_history=(select MAX(id_history) " \
                     "from databaseIOT.history_backup where id_account = %s limit %s)"
        val_backup = (id, 1)
        cur = mydb.cursor()
        cur.execute(sql_backup, val_backup)
        for record in cur.fetchall():
            print(record[0])
            return str(record[0])
        return "chưa có lần backup nào "
    return verify


def getListRetore(user):
    id = user.get('id')
    token = user.get('token')
    cur = mydb.cursor()
    sql_login = "select * from databaseIOT.history_backup where username = %s"
    val_login = (id)
    cur.execute(sql_login, val_login)
    for record in cur.fetchall():
        if check_password(token, record[5]):
            account = {
                "id": record[0],
                "token": record[5],
                "name": record[1],
                "email": record[2],
                "date_create": record[6]
            }
            print(account)
            return json.dumps(account)


"""
        for x in arr:
            size = os.path.getsize(path+"/"+x)
            info ={
                "name": x,
                "size": size
            }
            mang.append(info)"""


def getListData(acc):
    path = acc.get('path')
    verify = verificationAccount(acc)
    if verify:
        arr = os.listdir(path)
        mang = []
        for x in arr:
            size = os.path.getsize(path + "/" + x)
            info = {
                "name": x,
                "size": size
            }
            mang.append(info)
        list = {
            "list2": mang
        }
        print(list)
        return json.dumps(list)
    return verify


def renameBackup(acc):
    id = acc.get('id')
    id_history = acc.get('id_history')
    newname = acc.get('newname')
    print(id, id_history, newname)
    verify = verificationAccount(acc)
    if verify:
        sql_token = "update databaseIOT.history_backup set name_history = %s " \
                    "where id_history= %s and id_account = %s limit 1"
        val_token = (newname, id_history, id)
        updateDB(sql_token, val_token)
        return "True"
    return verify


def logintoken(user):
    id = user.get(ID_ACCOUNT)
    token = user.get(TOKEN)
    verify = verificationAccount(user)
    if verify:
        cur1 = mydb.cursor()
        sql_getkey = "select * from " + TABLE_ACCOUNT + " where id_account = %s limit %s "
        val_getkey = (id, LIMIT_QUERY)
        cur1.execute(sql_getkey, val_getkey)
        for record_key in cur1.fetchall():
            account = {
                ID_ACCOUNT: id,
                "name": record_key[1],
                USERNAME: record_key[3],
                'email': record_key[2],
                TOKEN: token,
                "date_create": record_key[6]
            }
            return convertJSON(200, True, account)
        return verify
    # ====================================================


# Kiểm tra mã code
# return : True , False , Overtime , NotCode
def checkCodeVerify(user):
    id = user.get(ID_ACCOUNT)
    code = user.get('code')
    email = user.get(EMAIL)
    if id is None or email is None or code is None:
        return convertJSON(CODE_NULL, False, RETURN_NONE)
    if not id or not email or not code:
        return convertJSON(CODE_EMPTY, False, ERROR_EMPTY)
    cur = mydb.cursor()
    sql_login = "select code_verify,date_create from " + TABLE_SAVE_CODE + \
                " where id_account = %s && username = %s limit %s"
    val_login = (id, email, LIMIT_QUERY)
    cur.execute(sql_login, val_login)
    for record in cur.fetchall():
        if record[0] is None:
            return convertJSON(1101, False, "Not code")
        if record[1] is None or compareTime(float(record[1]), TIME_VERYCODE) is not True:
            return convertJSON(1102, False, "Code expired ")
        if str(code) == str(record[0]):
            val_update = (None, None, id, LIMIT_QUERY)
            updateDB(UPDATE_CODE_BY_ID_ACCOUNT, val_update)
            return RETURN_TRUE
        return convertJSON(1113, False, "Code wrong ")
    return convertJSON(1007, False, "Type is incorrect")


"""
Bkav Tiennvh: 

 
"""


# Xác thực account bằng token
def verificationAccount(user):
    id = user.get(ID_ACCOUNT)
    token = user.get(TOKEN)
    # Bkav Tiennvh: Check params
    if id is None or token is None:
        return convertJSON(CODE_NULL, False, RETURN_NONE)
    if not id or not token:
        return convertJSON(CODE_EMPTY, False, ERROR_EMPTY)
    cur1 = mydb.cursor()
    sql_getkey = "select * from " + TABLE_ACCOUNT + " where id_account = %s limit %s "
    val_getkey = (id, LIMIT_QUERY)
    cur1.execute(sql_getkey, val_getkey)
    for record_key in cur1.fetchall():
        key = str(record_key[4])
        try:
            decode_token = jwt.decode(token, key, algorithms=['HS256'])
            print("Token is still valid and active" + str(decode_token))
            return RETURN_TRUE
        except jwt.ExpiredSignatureError:
            print("Token expired. Get new one")
            return convertJSON(1103, False, "Account token expired ")
        except jwt.InvalidTokenError:
            print("Invalid Token")
            return convertJSON(1104, False, "Account token invalid")
    return convertJSON(CODE_USER_NOT_EXIT, False, RETURN_USER_NOT_EXIT)


# Bkav Tiennvh: Gửi email
def send_email(sendto, code):
    from email.message import EmailMessage
    username = "tiennvh98@gmail.com"
    password = "tien240598"
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Backup Verification code for resetting password"
    msg['From'] = username
    msg['To'] = sendto
    try:
        print("Sending Email to {} (trial {})...")
        import smtplib
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(username, password)
        html_message = render_template('index.html', test=sendto, code_verify=code)
        message = MIMEText(html_message, "html")
        msg.attach(message)
        server.sendmail(username, sendto, msg.as_string())
        server.quit()
        print("Email sent!")
        return True
    except Exception as e:
        print("Failed to send email due to Exception:" + str(e))
        return False

    """
      phn = "Tiennvh98@gmail.com"
      Bkav Tiennvh:  regex password ^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\S+$).{9,}$
      ^                 # start-of-string
      (?=.*[0-9])       # a digit must occur at least once
      (?=.*[a-z])       # a lower case letter must occur at least once
      (?=.*[A-Z])       # an upper case letter must occur at least once
      (?=.*[@#$%^&+=])  # a special character must occur at least once
      (?=\S+$)          # no whitespace allowed in the entire string
      .{9,}             # anything, at least eight places though
      $                 # end-of-string
      Bkav TienNVh:^([_a-zA-Z0-9-]+(\\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*(\\.[a-zA-Z]{1,6}))?$

      if re.search("", phn):
          print("Valid phone number")
          return phn
      return "FALSE"
    """


def checkStandard(text, type):
    if type == EMAIL:
        regex = "^([_a-zA-Z0-9-]+(\\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*(\\.[a-zA-Z]{1,6}))?$"
    elif type == PASSWORD:
        regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\S+$).{9,}$"
    else:
        return False
    if re.search(regex, text):
        return True
    return False


# Bkav Tiennvh: chuyển sang kiểu json để trả dữ liệu về
def convertJSON(code, success, result):
    account = {
        "code": code,
        "success": success,
        "result": result
    }
    return json.dumps(account)


# Bkav Tiennvh:Kiểm tra thời gian còn hạn ko ?
def compareTime(date_create, valid):
    ts = datetime.now().timestamp()
    deadline = ts - date_create
    if int(deadline) < valid:
        return True
    return False


# Thuc thi update
def updateDB(sql, val):
    cur = mydb.cursor()
    cur.execute(sql, val)
    mydb.commit()
    return True


# Thuc thi select
def selectDB(sql, val):
    cur = mydb.cursor()
    cur.execute(sql, val)
    # for record in cur.fetchall():
    return cur


# Thuc thi insert
def insert(sql, val):
    cur = mydb.cursor()
    cur.execute(sql, val)
    mydb.commit()
    return


def getTimeNow():
    now = datetime.now()
    # %H:%M:%S %d/%m/%Y
    dt_string = now.strftime("%H:%M:%S %d/%m/%Y")
    return dt_string


# plain_text_password ; string
def get_hashed_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    return bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt(12))


def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))
