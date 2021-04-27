import mysql.connector
import jwt
import json
import bcrypt
import os
from datetime import datetime

mydb = mysql.connector.connect(
    host="localhost",
    user="servercloud",
    password="123456a@A",
    auth_plugin='mysql_native_password'
)
#user = "root",
#password = "Tiennvh98@"

def register( user):
    name = user.get('name')
    email = user.get('email')
    username = user.get('username')
    password = user.get('password')
    sql_login = "select * from databaseIOT.account where username = %s limit %s"
    val_login = (username,1)
    cur = mydb.cursor()
    isExit = False
    cur.execute(sql_login, val_login)
    for record in cur.fetchall():
        isExit = True

    if(isExit == False):
        try:
            password_code = get_hashed_password(password);
            sql_register = "INSERT INTO databaseIOT.account (name_account, email_account, username, password, date_create) VALUES (%s, %s, %s, %s, %s)"
            val_register = (name, email, username, password_code, getTimeNow())
            updateDB(sql_register, val_register)
            return "True"
        except:
            return "False"
    return "Duplicate"

def logintokent(user):
    id = user.get('id')
    token = user.get('token')
    cur = mydb.cursor()
    sql_login = "select * from databaseIOT.account where id_account = %s && token= %s "
    val_login = (id, token)
    cur.execute(sql_login, val_login)
    list =[]
    for record in cur.fetchall():
        account={
            "id": record[0],
            "name": record[2],
            "email": record[3],
            "date_create": record[6]
        }
        list.append(account)
        return json.dumps(list)
    return "False"

def loginaccount(user):
    username = user.get('username')
    password = user.get('password')
    cur = mydb.cursor()
    print(username+"//"+password)
    #Check  Account
    sql_login = "select * from databaseIOT.account where username = %s limit %s"
    val_login = (username ,1)
    cur.execute(sql_login, val_login)
    for record in cur.fetchall():
         if(check_password(password ,record[4])):
            key = record[3] + record[4]
            token = jwt.encode({'id': record[0],
                                'name': record[1],
                                'email': record[2],
                                'date create': record[6]
                                }, key)
            #update token and active
            sql_token = "update databaseIOT.account set token = %s  where id_account= %s limit 1"
            val_token = (token, record[0])
            updateDB(sql_token, val_token)
            account = {
                 "id": record[0],
                 "token":record[5],
                 "name": record[1],
                 "email": record[2],
                 "date_create": record[6]
             }
            print(account)
    return json.dumps(account)

def logOut(acc):
    id = acc.get('id')
    if(verificationAccount(acc)):
        sql_token = "update databaseIOT.account set token = %s  where id_account= %s limit 1"
        val_token = (0,id)
        updateDB(sql_token, val_token)


#=======================Backup===========


def insertBackup(acc):
    id = acc.get('id')
    namebackup = acc.get('namebackup')
    namedevice = acc.get("namedevice")
    path = acc.get("path")
    if(verificationAccount(acc)):
        sql_insert = "INSERT INTO databaseIOT.history_backup (name_history, date_backup, devices_backup, id_account, path_backup) VALUES (%s, %s, %s, %s, %s)"
        val_insert = (namebackup, getTimeNow(), namedevice, id, path)
        updateDB(sql_insert, val_insert)


def removeBackup(acc):
    path = acc.get('pathsave')
    nameFolder = acc.get('namefolder')
    id_history = acc.get('id_history')
    if(verificationAccount(acc)):
         #delete foldersplit
        os.rmdir(os.path.join(path,nameFolder))
        # update mysql
        sql = "DELETE FROM databaseIOT.history_backup WHERE id_history =%s limit %s"
        val = (id_history, 1)
        cur = mydb.cursor()
        cur.execute(sql, val)
        mydb.commit()
        return "True"

def getListBackup(acc):
    id = acc.get('id')
    if(verificationAccount(acc)):
        sql = "select *  from databaseIOT.history_backup where id_account = %s limit %s"
        val = (id, 100)
        cur = mydb.cursor()
        cur.execute(sql,val)
        alist = []
        for record in cur.fetchall():
            account = {
                 "id_history": record[0],
                 "name_history":record[1],
                 "date_backup": record[2],
                 "devices_backup": record[3],
                 "pathsave": record[5]
             }
            print(account)
            alist.append(account)
        data_set ={"content": alist}
        return json.dumps(data_set)

def backuplast(acc):
    id = acc.get('id')
    if(verificationAccount(acc)):
        sql_backup ="select date_backup from databaseIOT.history_backup where id_history=(select MAX(id_history) from databaseIOT.history_backup where id_account = %s limit %s)"
        val_backup = (id,1)
        cur = mydb.cursor()
        cur.execute(sql_backup, val_backup)
        for record in cur.fetchall():
            print(record[0])
            return str(record[0])

def getListRetore(user):
      id = user.get('id')
      token =  user.get('token')
      cur = mydb.cursor()
      sql_login = "select * from databaseIOT.history_backup where username = %s"
      val_login = (id)
      cur.execute(sql_login, val_login)
      for record in cur.fetchall():
       if(check_password(token ,record[5])):
            account = {
                 "id": record[0],
                 "token":record[5],
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
    if(True):
        arr = os.listdir(path)
        mang =[]
        for x in arr:
            size = os.path.getsize(path + "/" + x)
            info = {
                "name": x,
                "size": size
            }
            mang.append(info)


        list ={
        "list2":mang
        }
        print(list)
        return json.dumps(list)

def renameBackup(acc):
    id = acc.get('id')
    id_history = acc.get('id_history')
    newname = acc.get('newname')
    print(id, id_history, newname)
    if(verificationAccount(acc)):
         sql_token = "update databaseIOT.history_backup set name_history = %s where id_history= %s and id_account = %s limit 1"
         val_token = (newname , id_history, id)
         updateDB(sql_token, val_token)
         return "True"
    return "False"



#====================================================
def verificationAccount(acc):
    id = acc.get('id')
    token = acc.get('token')
    cur = mydb.cursor()
    sql_login = "select * from databaseIOT.account where id_account = %s && token = %s"
    val_login = (id,token)
    cur.execute(sql_login, val_login)
    for record in cur.fetchall():
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
    # dd/mm/YY H:M:S
    dt_string = now.strftime(" %S:%M:%H %d/%m/%Y")
    return dt_string

# plain_text_password ; string
def get_hashed_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    return bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt( 12 ))

def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))

