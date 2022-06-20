# -*- coding: utf-8 -*-
import time
from flask import Flask, render_template, request, url_for, flash, redirect, session, send_file  # , escape
import sqlite3
import hashlib
import os
from werkzeug.utils import secure_filename
from pathlib import Path
import shutil
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from base64 import b64encode
import zipfile
import io

# TODO
#  Bei Kategorie löschen "Bitte Auswählen" in "vorhandene Dateien löschen" ändern und entsprechende Funktion einfügen


app = Flask(__name__)
application = app  # Erforderlich für Apache WSGI
app.config['SECRET_KEY'] = 'lkjeflohg3qpghlvhboi<a'  # Für Produktiv-Systeme auf jeden Fall ändern
basedir = "data"

apppath = os.path.abspath('app.py')
workdir = os.path.dirname(__file__)
basedir = os.path.join(workdir, basedir)
database = os.path.join(workdir, 'dms_data.db')  # Erforderlich für die Erreichbarkeit der Datenbank außerhalb von PC


@app.route('/lostpw', methods=('GET', 'POST'))
def lostpw():
    if request.method == 'POST':
        username = request.form['name']
        sql = """SELECT * FROM users WHERE loginname =? """
        params = (username, )
        conn = sqlite3.connect(database)
        c = conn.cursor()
        userdata = c.execute(sql, params).fetchone()
        email = userdata[6]
        if not email:
            flash("Sie haben keine eMailadresse in ihr Profil eingegeben. Bitte bitten Sie den Administrator Ihren "
                 "ein neues Passwort zu generieren.")
            return render_template('index.html')

        dbname = userdata[2]
        salt = userdata[4]

        conn.close()
        dbextensions, dbmailserver, dbmailport, dbmailname, dbmailfrom, dbmailtext, dbmailpw, dbmailsubject = load_settings()
        message = dbmailtext
        newpw = gen_newpw(username, salt)
        message = message.replace("{name}", str(dbname))
        message = message.replace("{pw}", str(newpw))
        s = smtplib.SMTP(host=dbmailserver, port=dbmailport)
        s.starttls()
        s.login(dbmailname, dbmailpw)
        msg = MIMEMultipart()
        msg['From'] = dbmailfrom
        msg['To'] = email
        msg['Subject'] = dbmailsubject
        msg.attach(MIMEText(message, 'plain'))
        try:
            s.send_message(msg)
            flash("Das neue Passwort ist per eMail unterwegs...")

        except smtplib.SMTPAuthenticationError:
            flash("Das Mailsystem ist nicht korrekt konfiguriert! Der Benutzername oder das Passwort sind falsch!")

        except smtplib.SMTPRecipientsRefused:
            flash("Die in ihr Profil enthaltene eMailadresse ist ungültig! "
                  "Bitte bitten Sie den Administrator das Passwort zu ändern!")
        del msg

        return render_template('lostpw.html')

    return render_template('lostpw.html')


@app.route('/settings', methods=('GET', 'POST'))
def settings():
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isadmin = is_admin()
    if not isadmin:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    dbextensions, dbmailserver, dbmailport, dbmailname, dbmailfrom, dbmailtext, dbmailpw, dbmailsubject= load_settings()

    if request.method == 'POST':
        extensions = request.form['extensions']
        mailserver = request.form['mailserver']
        mailport = request.form['mailport']
        mailname = request.form['mailname']
        mailpw = request.form['mailpw']
        mailfrom = request.form['mailfrom']
        mailtext = request.form['mailtext']
        mailsubject = request.form['mailsubject']

        save_settings(extensions, mailserver, mailport, mailname, mailpw, mailfrom, mailtext, mailsubject)
        flash("Einstellungen gespeichert")
        return render_template("settings.html", isadmin=isadmin, dbextensions=dbextensions, dbmailserver=dbmailserver,
                               dbmailport=dbmailport, dbmailname=dbmailname, dbmailfrom=dbmailfrom,
                               dbmailtext=dbmailtext, dbmailpw=dbmailpw, dbmailsubject=dbmailsubject)

    return render_template("settings.html", isadmin=isadmin, dbextensions=dbextensions, dbmailserver=dbmailserver,
                           dbmailport=dbmailport, dbmailname=dbmailname, dbmailfrom=dbmailfrom, dbmailtext=dbmailtext,
                           dbmailpw=dbmailpw, dbmailsubject=dbmailsubject)


@app.route('/edit_user/<userid>', methods=('GET', 'POST'))
def edit_user(userid):
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isadmin = is_admin()
    if not isadmin:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    conn = sqlite3.connect(database)
    c = conn.cursor()
    permission = is_admin()
    if not permission:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    user = c.execute('SELECT * FROM users WHERE id = ?', (userid,)).fetchone()
    id = user[0]
    pwhash = user[5]
    dbname = user[2]
    dbrole = user[3]
    dbemail = user[6]
    salt = user[4]
    conn.close()

    if request.method == 'POST':
        name = request.form['name']
        password1 = request.form['password1']
        password2 = request.form['password2']
        email = request.form['email']
        role = request.form['role']

        if password1 != password2:
            flash("Die Passwörter stimmen nicht überein!")
            return render_template('edit_user.html', name=dbname, role=dbrole, email=dbemail, userid=id,
                                   permission=permission)

        if role == "Bitte wählen!":
            role = dbrole

        if password1:
            salt = os.urandom(10)
            pwhash = hashlib.pbkdf2_hmac('sha512', password1.encode(), salt, 10)

        if role == "Administrator":
            role = "admin"
        if role == "Leser":
            role = "readonly"
        if role == "Leser und Schreiber":
            role = "user"

        conn = sqlite3.connect(database)
        c = conn.cursor()
        c.execute("""UPDATE users SET name=?, role=?, salt= ?,passwd=?, email=? WHERE id = ?""",
                  (name, role, salt, pwhash, email, id))
        conn.commit()
        conn.close()
        users = get_all_users()
        return render_template('show_users.html', users=users)

    return render_template('edit_user.html', name=dbname, role=dbrole, email=dbemail, userid=id)


@app.route('/delete_user', methods=('GET', 'POST'))
def delete_user():
    isadmin = is_admin()
    if not isadmin:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    userid = request.args.get("userid")
    conn = sqlite3.connect(database)
    c = conn.cursor()
    params = (userid,)
    sql = """DELETE FROM users WHERE ID is ?"""
    c.execute(sql, params)
    conn.commit()
    conn.close()
    users = get_all_users()
    return render_template('show_users.html', users=users)


@app.route('/show_users', methods=('GET', 'POST'))
def show_users():
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isadmin = is_admin()
    if not isadmin:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    users = get_all_users()

    return render_template('show_users.html', users=users)


@app.route('/adduser', methods=('GET', 'POST'))
def adduser():
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isadmin = is_admin()
    if not isadmin:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    if request.method == 'POST':
        name = request.form['name']
        logname = request.form['logname'].lower()
        password1 = request.form['password1']
        password2 = request.form['password2']
        email = request.form['email']
        role = request.form['role']
        salt = os.urandom(10)

        if role == "Administrator":
            role = "admin"
        if role == "Leser":
            role = "readonly"
        if role == "Leser und Schreiber":
            role = "user"

        if password1 != password2:
            flash("Die Passwörter stimmen nicht überein!")
            return render_template('adduser.html', name=name, logname=logname, email=email)

        if role == "Bitte wählen!":
            flash("Bitte wählen Sie eine Rolle aus!")
            return render_template('adduser.html', name=name, logname=logname, email=email)

        pwhash = hashlib.pbkdf2_hmac('sha512', password1.encode(), salt, 10)
        conn = sqlite3.connect(database)
        c = conn.cursor()
        params = (logname, name, role, salt, pwhash, email)
        sql = """INSERT INTO users (loginname,name,role,salt,passwd,email) VALUES (?, ?, ?, ?, ?, ?)"""

        try:
            c.execute(sql, params)
            conn.commit()
            conn.close()

        except sqlite3.IntegrityError:
            flash("Benutzername schon vergeben!")

        flash("Benutzer erfolgreich hinzugefügt!")
        users = get_all_users()
        return render_template('show_users.html', users=users)

    return render_template('adduser.html')


@app.route('/profile', methods=('GET', 'POST'))
def profile():
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))
    isreadonly = is_readonly()
    isadmin = is_admin()

    conn = sqlite3.connect(database)
    c = conn.cursor()
    name = session["name"]
    params = (name,)
    sql = """SELECT * FROM users where loginname is ? """
    c.execute(sql, params)
    data = c.fetchone()

    fullname = data[2]
    dbsalt = data[4]
    dbpass = data[5]
    dbrole = data[3]
    dbemail = data[6]

    if request.method == 'POST':
        oldpassword = dbpass
        oldpwform = request.form['oldpassword']
        password1 = request.form['password1']
        password2 = request.form['password2']
        email = request.form['email']

        if email != dbemail:
            c.execute("""UPDATE users SET email=? WHERE loginname = ?""",
                      (email, name))
            conn.commit()
            flash("eMailadresse wurde geändert!")

        if password1:
            if not password2:
                flash('Bitte Passwort wiederholen!')

            if password1 != password2:
                flash("Die Passwörter stimmen nicht überein!")
            newpw = hashlib.pbkdf2_hmac('sha512', password1.encode(), dbsalt, 10)

            oldpwok = check_pw(oldpwform, oldpassword, dbsalt)

            if oldpwok:

                session["name"] = name
                session["password"] = newpw
                session["role"] = dbrole
                session["fullname"] = fullname
                c.execute("""UPDATE users SET passwd=? WHERE loginname = ?""", (newpw, name))
                conn.commit()
                conn.close()

            else:
                flash("Das alte Passwort wurde falsch eingegeben")
                return render_template('profile.html', email=dbemail, role=dbrole)

            flash("Ihr Kennwort wurde geändert!")

            return render_template('profile.html', email=email, role=dbrole)

    return render_template('profile.html', email=dbemail, role=dbrole, isreadonly=isreadonly, isadmin=isadmin)


@app.route('/admin')
def admin():
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isadmin = is_admin()
    users, categories, docs, dbsizekb, dbsizemb = admin_statistics()
    sizebytes, sizemb, sizegb = get_uploadsize()

    if isadmin:
        return render_template('admin.html', isadmin=isadmin, users=users, categories=categories, docs=docs,
                               dbsizekb=dbsizekb, dbsizemb=dbsizemb, sizebytes=sizebytes, sizemb=sizemb, sizegb=sizegb)
    else:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")


@app.route('/add_cat', methods=('GET', 'POST'))
def add_cat():
    conn = sqlite3.connect(database)
    c = conn.cursor()

    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isadmin = is_admin()
    if not isadmin:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    if request.method == 'POST':
        newcatname = request.form['newcatname']
        newcatpath = request.form['newcatpath']

        if not newcatname:
            flash("Der Name der Kategorie muss ausgefüllt sein!")

        if not newcatpath:
            flash("Der Pfad der Kategorie muss ausgefüllt sein!")

        notallowed = "/\\"
        newcatpath = newcatpath.strip(notallowed)
        chars = {'ö': 'oe', 'ä': 'ae', 'ü': 'ue', 'Ü': 'Ue', 'Ö': 'Oe', 'Ä': 'Ae', 'ß': 'ss'}

        for char in chars:
            newcatpath = newcatpath.replace(char, chars[char])

        completepath = os.path.join(basedir, newcatpath)
        completepath = completepath.encode(encoding='UTF-8', errors='strict')
        try:
            if not os.path.exists(completepath):
                os.mkdir(completepath)
        except:
            flash("Es ist ein Fehler beim Erstellen des Ordners aufgetreten")

        params = (newcatname, newcatpath)
        try:
            sql = """INSERT INTO category (catname, path) VALUES (?, ?)"""
            c.execute(sql, params)
            conn.commit()
            conn.close()

        except sqlite3.IntegrityError:
            flash("Kategorie existiert bereits!")

        except sqlite3.OperationalError:
            flash("Es gab ein Problem mit der Datenbank, bitte probieren Sie es später nochmal!")


    return render_template('add_cat.html', isadmin=isadmin)


@app.route('/delcat', methods=('GET', 'POST'))
def del_cat():
    category = get_category()
    conn = sqlite3.connect(database)
    c = conn.cursor()
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isadmin = is_admin()
    if not isadmin:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    if request.method == 'POST':
        cat = request.form['cat']
        destcat = request.form['destcat']
        if cat == "default":
            flash("Diese Kategorie kann nicht gelöscht werden!")
            return render_template('delete_cat.html', category=category)

        if cat == "Bitte wählen!":
            flash("Sie müssen eine Kategorie auswählen!")
            return render_template('delete_cat.html', category=category)

        sql = """SELECT path FROM category WHERE catname is ?"""
        params = (cat, )
        c.execute(sql, params)

        sourcedir = c.fetchone()
        sourcedir = sourcedir[0]
        scriptdir = os.path.abspath(".")
        sourcedir = os.path.join(scriptdir, basedir, sourcedir)

        sql = """SELECT path FROM category WHERE catname is ?"""
        params = (destcat,)
        c.execute(sql, params)
        destdir = c.fetchone()
        destdir = destdir[0]
        scriptdir = os.path.abspath(".")

        destdir = os.path.join(scriptdir, basedir, destdir)

        files = os.listdir(sourcedir)
        try:
            for file in files:
                params = (destcat, file)
                sql = """UPDATE docs set category = ? WHERE filename is ?"""
                c.execute(sql, params)
                conn.commit()
                shutil.move(f"{sourcedir}/{file}", destdir)
                conn.close()

        except OSError as e:
            flash(str(e))
        else:
            flash("Dateien verschoben!")

        try:
            shutil.rmtree(sourcedir)
        except OSError as e:
            print(e)
        else:
            flash("Kategorie erfolgreich gelöscht")

        params = (cat,)
        sql = """DELETE FROM category WHERE catname is ?"""
        c.execute(sql, params)
        conn.commit()
        conn.close()
        category = get_category()
        time.sleep(1)
        return render_template('delete_cat.html', category=category)

    return render_template('delete_cat.html', category=category, isadmin=isadmin)


@app.route('/', methods=('GET', 'POST'))
def index():
    if 'name' in session:
        return redirect(url_for("welcome"))

    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        name = name.lower()

        if 'name' in session:
            return render_template('welcome.html')

        if not name:
            flash('Name wird benötigt!')
            return render_template('index.html')

        if not password:
            flash('Passwort wird benötigt')
            return render_template('index.html')

        conn = sqlite3.connect(database)
        c = conn.cursor()
        params = (name,)

        sql = """SELECT * FROM users where loginname is ? """
        c.execute(sql, params)
        data = c.fetchone()
        conn.close()
        if not data:
            flash("Der Benutzername ist nicht in der Datenbank enthalten!")
            return render_template('index.html')

        dbsalt = data[4]
        dbpass = data[5]

        loginok = check_pw(password, dbpass, dbsalt)

        if loginok:
            fullname = data[2]
            dbrole = data[3]
            session["name"] = request.form["name"]
            session["password"] = request.form["password"]
            session["role"] = dbrole
            session["fullname"] = fullname
            return redirect(url_for('welcome', fullname=fullname))
        else:
            flash('Passwort ist falsch')
            return render_template('index.html')

    return render_template("index.html", methods=('GET', 'POST'))


@app.route('/edit/<docid>', methods=('GET', 'POST'))
def edit(docid):
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isreadonly = is_readonly()
    isadmin = is_admin()
    name = session["name"]
    users = get_users()
    isowner = is_owner(name, docid)
    if isreadonly:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    current_data = get_dokument(docid)
    currdocname = current_data[4]
    currkeywords = current_data[2]
    currcategory = current_data[5]
    filename = current_data[1]
    categorys = get_category()
    sortedcat = []

    for cat in categorys:
        if cat[1] != currcategory:
            sortedcat.append(cat)

    if request.method == "POST":
        docname = request.form['docname']
        keywords = request.form['keywords']
        newcategory = request.form['cat']

        if request.form.get("private"):
            private = True
        else:
            private = False

        if docname == "":
            docname = currdocname

        if keywords == "":
            keywords = currkeywords

        if newcategory != currcategory:
            # Gibt den kompletten Pfad eine angegebene Kategorie aus
            conn = sqlite3.connect(database)
            c = conn.cursor()
            sql = """SELECT path FROM category where catname is ?"""
            params = (newcategory, )
            c.execute(sql, params)

            folder = c.fetchone()
            folder = folder[0]
            newcatpath = os.path.join(basedir, folder)
            oldcatpath = get_filepath(filename)
            oldpath = os.path.join(basedir, oldcatpath, filename)
            newpath = os.path.join(newcatpath, filename)

            try:
                shutil.move(oldpath, newpath)
            except OSError as e:
                flash(str(e))

        flash("Dokument geändert")
        print(private)
        conn = sqlite3.connect(database)
        c = conn.cursor()
        c.execute("""UPDATE docs SET doc_name=?, keywords=?, category=?, private=? WHERE id = ?""", (docname, keywords,
                                                                                          newcategory, private, docid))
        conn.commit()
        conn.close()

        return redirect(url_for("show_docs"))

    return render_template('edit.html', currdocname=currdocname, currkeywords=currkeywords, docid=docid,
                           currcategory=currcategory, categorys=sortedcat, isadmin=isadmin, isowner=isowner,
                           users=users)


@app.route('/delete', methods=('GET', 'POST'))
def delete():
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    isreadonly = is_readonly()
    if isreadonly:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    docid = request.args.get("docid")
    conn = sqlite3.connect(database)
    c = conn.cursor()
    params = (docid,)
    filename = c.execute("""SELECT filename from docs WHERE ID=?""", (docid,)).fetchone()
    cat = c.execute("""SELECT category from docs WHERE ID=?""", (docid,)).fetchone()
    cat = cat[0]
    folder = c.execute("""SELECT path from category WHERE catname=?""", (cat,)).fetchone()
    filename = filename[0]
    folder = folder[0]

    delfile = os.path.join(basedir, folder, filename)

    try:
        os.remove(delfile)
    except:
        flash("Datei konnte nicht gelöscht werden!")

    sql = """DELETE from docs WHERE ID=?"""
    c.execute(sql, params)
    conn.commit()
    conn.close()
    flash("Dokument gelöscht!!!")
    return redirect(url_for("show_docs"))


@app.route('/download/<filename>')
def return_files(filename):
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    private = is_private(filename)

    if private:
        ok = check_permissions(filename)

        if not ok:
            return render_template("forbidden.html")

    filepath = get_filepath(filename)
    downname = os.path.join(basedir, filepath, filename)
    namezip = filename + '.zip'
    downfile = os.path.join(basedir, filepath, namezip)
    # Die Datei muss gepackt werden, damit diese vom Browser ausgeliefert und nicht angezeigt wird
    zipper = zipfile.ZipFile(downfile, 'w')
    zipper.write(downname, filename, zipfile.ZIP_DEFLATED)
    zipper.close()

    return_data = io.BytesIO()
    with open(downfile, 'rb') as fo:
        return_data.write(fo.read())  # Die Datei wird in den Speicher geladen

    return_data.seek(0)  # Den Curser nach dem Starten wieder zum Anfang bewegen
    os.remove(downfile)  # Die Datei kann jetzt gelöscht werden, da diese im Speicher ist

    return send_file(return_data, as_attachment=True, attachment_filename=namezip)


@app.route('/open/<filename>')
def open_files(filename):
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    private = is_private(filename)

    if private:
        ok = check_permissions(filename)

        if not ok:
            return render_template("forbidden.html")

    filepath = get_filepath(filename)
    downname = os.path.join(basedir, filepath, filename)
    return send_file(downname, attachment_filename=filename)


@app.route('/show_docs')
def show_docs():
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    conn = sqlite3.connect(database)
    c = conn.cursor()
    name = session["name"]
    private = 0
    isadmin = is_admin()

    if not is_admin():
        params = (name, private)
        sql = """SELECT * FROM docs WHERE owner = ? OR private = ?"""
        c.execute(sql, params)
    else:
        sql = """SELECT * FROM docs"""
        c.execute(sql)

    docs = c.fetchall()
    conn.close()
    isreadonly = is_readonly()

    return render_template('show_docs.html', isadmin=isadmin, docs=docs, isreadonly=isreadonly)


@app.route('/welcome', methods=('GET', 'POST'))
def welcome():
    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    conn = sqlite3.connect(database)
    c = conn.cursor()
    name = session["name"]

    params = (name, )
    sql = """SELECT name from users where loginname is ?"""
    c.execute(sql, params)
    fullname = c.fetchone()[0]
    conn.close()
    categorys = get_category()

    if request.method == 'POST':
        conn = sqlite3.connect(database)
        c = conn.cursor()
        searchstring = request.form['searchdoc']
        searchstring = "%" + searchstring.lower() + "%"
        cats = request.form['cats']

        if cats == "alle":
            if not is_admin():
                params = (searchstring, name)
                # sql = """SELECT * FROM docs WHERE LOWER (keywords) like ? AND owner = ? OR private = 0"""
                sql = """SELECT * FROM docs WHERE LOWER (keywords) like ? AND (owner = ? OR private = 0)"""
                c.execute(sql, params)
                docs = c.fetchall()
                # sql = """SELECT * FROM docs WHERE LOWER (doc_name) like ?  AND owner = ? OR private = 0"""
                sql = """SELECT * FROM docs WHERE LOWER (doc_name) like ?  AND (owner = ? OR private = 0)"""
                c.execute(sql, params)
                docs1 = c.fetchall()
            else:
                params = (searchstring, )
                sql = """SELECT * FROM docs WHERE LOWER (keywords) like ?"""
                c.execute(sql, params)
                docs = c.fetchall()
                sql = """SELECT * FROM docs WHERE LOWER (doc_name) like ?"""
                c.execute(sql, params)
                docs1 = c.fetchall()

        else:
            params = (name, searchstring, cats)
            # sql = """SELECT * FROM docs WHERE LOWER (keywords) like ? and category is ?"""
            sql = """SELECT * FROM (SELECT * FROM docs WHERE owner = ? OR private = 0) WHERE LOWER (keywords) like ? AND category IS ?"""
            c.execute(sql, params)
            docs = c.fetchall()
            # sql = """SELECT * FROM docs WHERE LOWER (doc_name) like ? and category is ?"""
            sql = """SELECT * FROM (SELECT * FROM docs WHERE owner = ? OR private = 0) WHERE LOWER (doc_name) like ? AND category IS ?"""
            c.execute(sql, params)
            docs1 = c.fetchall()

        if searchstring == "":

            if is_admin():
                if cats == "alle":
                    sql = """SELECT * FROM docs"""
                    c.execute(sql)
                else:
                    params = (cats,)
                    sql = """SELECT * FROM docs WHERE category is ?"""
                    c.execute(sql, params)
                docs1 = c.fetchall()

            else:
                if cats == "alle":
                    params = (name, )
                    sql = """SELECT * FROM docs WHERE owner = ? OR private = 0"""
                    c.execute(sql, params)
                else:
                    params = (cats, name)
                    sql = """SELECT * FROM docs WHERE category is ? AND owner = ? OR private = 0"""
                    c.execute(sql, params)
                docs1 = c.fetchall()

        conn.close()
        docsall = docs + docs1
        docssorted = []
        for element in docsall:
            if element not in docssorted:
                docssorted.append(element)

        isadmin = is_admin()
        isreadonly = is_readonly()
        return render_template("search_docs.html", docs=docssorted, fullname=fullname, isadmin=isadmin,
                               isreadonly=isreadonly)

    isadmin = is_admin()
    isreadonly = is_readonly()

    return render_template("welcome.html", fullname=fullname, isadmin=isadmin, isreadonly=isreadonly,
                           categorys=categorys)


@app.route('/add_doc', methods=('GET', 'POST'))
def add_doc():
    conn = sqlite3.connect(database)
    c = conn.cursor()
    category = get_category()
    isreadonly = is_readonly()
    isadmin = is_admin()
    allowed_extension = get_extensions()

    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    if isreadonly:
        flash("Keine Berechtigung!")
        return render_template("welcome.html")

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        selected_cat = request.form['cat']
        file = request.files["file"]
        name = session["name"]

        if selected_cat == "Bitte wählen!":
            selected_cat = "default"
        params = (selected_cat, )
        sql = """SELECT path FROM category WHERE catname is ?"""

        if request.form.get("private"):
            private = True
        else:
            private = False

        if not title:
            title = file.filename

        if not file:
            flash("Bitte wählen Sie eine Datei aus!")

        if file.filename == "":
            return redirect(request.url)

        if ext_allowed(file.filename):
            c.execute(sql, params)
            folder = c.fetchone()
            folder = str(folder[0])
            folder = folder
            filename = secure_filename(file.filename)
            completepath = os.path.join(basedir, folder, filename)
            if os.path.exists(completepath):
                filename = modify_filename(filename)

            file.save(completepath)
            date = str(time.strftime("%d.%m.%Y-%H:%M:%S"))
            conn = sqlite3.connect(database)
            c = conn.cursor()
            params = (filename, content, date, title, selected_cat, name, private)
            sql = """INSERT INTO docs (filename, keywords, mod_date, doc_name, category, owner, private) VALUES (?, ?, ?, ?, ?, ?, ?)"""
            c.execute(sql, params)
            conn.commit()
            conn.close()
            flash(f"Dokument \"{title}\" erfolgreich hochgeladen!")
            return render_template('add_doc.html', isadmin=isadmin, category=category,
                                   allowed_extension=allowed_extension)
        else:
            flash("Ungültige Dateiendung!")

    return render_template('add_doc.html', category=category, allowed_extension=allowed_extension, isadmin=isadmin)


@app.route('/logout')
def logout():
    isreadonly = is_readonly()
    return render_template('logout.html', isreadonly=isreadonly)


@app.route('/do_logout')
def do_logout():
    session.pop("name", None)
    return redirect(url_for('index'))


@app.route('/about')
def about():
    return render_template("about.html")


def gen_salt():
    return os.urandom(10)


def hash_pw(password, salt):
    return hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 10)


def check_pw(password, hash, salt):
    pw_hash = hash_pw(password, salt)
    return pw_hash == hash


def get_dokument(doc_id):
    conn = sqlite3.connect(database)
    c = conn.cursor()
    document = c.execute('SELECT * FROM docs WHERE id = ?', (doc_id,)).fetchone()
    conn.close()
    return document


def ext_allowed(filename):
    extensions = get_extensions()
    return "." in filename and filename.rsplit(".", 1)[1].lower() in extensions


def get_extensions():
    conn = sqlite3.connect(database)
    c = conn.cursor()
    sql = """SELECT extensions from settings"""
    c.execute(sql)
    extensions = c.fetchone()
    extensions = extensions[0]

    return extensions


def is_admin():
    role = session["role"]
    if role == "admin":
        return True
    if role != "admin":
        return False


def is_readonly():
    role = session["role"]
    if role == "readonly":
        return True
    if role != "readonly":
        return False


def gen_newpw(name, salt):
    pw = os.urandom(20)
    newpw = b64encode(pw).decode('utf-8')
    newhashpw = hash_pw(newpw, salt)
    conn = sqlite3.connect(database)
    c = conn.cursor()
    c.execute("""UPDATE users SET passwd=? WHERE loginname = ?""",
              (newhashpw, name))
    conn.commit()
    conn.close()

    return newpw


def save_settings(extensions, mailserver, mailport, mailname, mailpw, mailfrom, mailtext, mailsubject):
    conn = sqlite3.connect(database)
    c = conn.cursor()
    c.execute("""UPDATE settings SET extensions=?, mailserver=?, mailport= ?,mailname=?, mailpw=?, mailfrom=?, 
    mailtext=?, mailsubject=?""", (extensions, mailserver, mailport, mailname, mailpw, mailfrom, mailtext, mailsubject))
    conn.commit()
    conn.close()


def load_settings():
    conn = sqlite3.connect(database)
    c = conn.cursor()
    settings = c.execute('SELECT * FROM settings').fetchone()
    dbextensions = settings[1]
    dbmailserver = settings[2]
    dbmailport = settings[3]
    dbmailname = settings[4]
    dbmailfrom = settings[5]
    dbmailtext = settings[6]
    dbmailpw = settings[7]
    dbmailsubject = settings[8]
    conn.close()

    return dbextensions, dbmailserver, dbmailport, dbmailname, dbmailfrom, dbmailtext, dbmailpw, dbmailsubject


def get_filepath(filename):
    params = (filename, )
    conn = sqlite3.connect(database)
    c = conn.cursor()
    sql = """SELECT category FROM docs WHERE filename is ?"""
    c.execute(sql, params)
    category = c.fetchone()
    category = category[0]
    params = (category, )
    sql = """SELECT path FROM category WHERE catname is ?"""
    c.execute(sql, params)
    filepath = c.fetchone()
    filepath = filepath[0]
    conn.close()
    return filepath


def modify_filename(filename):
    date = str(time.strftime("%d%m%Y-%H%M%S"))
    date = str(date)
    filename = Path(filename)
    purename = filename.stem
    suffix = filename.suffix
    filename = purename + "_" + date + suffix
    return filename


def get_category():
    sql = """SELECT * FROM category"""
    conn = sqlite3.connect(database)
    c = conn.cursor()
    c.execute(sql)
    category = c.fetchall()
    conn.close()
    return category

def get_users():
    sql = """SELECT * FROM users"""
    conn = sqlite3.connect(database)
    c = conn.cursor()
    c.execute(sql)
    users = c.fetchall()
    conn.close()
    return users


def get_all_users():
    conn = sqlite3.connect(database)
    c = conn.cursor()
    sql = """SELECT * FROM users"""
    c.execute(sql)
    users = c.fetchall()
    conn.close()
    return users


def is_owner(name, docid):
    conn = sqlite3.connect(database)
    c = conn.cursor()
    params = (docid, )
    sql = """SELECT owner FROM docs WHERE ID=?"""
    c.execute(sql, params)
    owner = c.fetchone()
    owner = owner[0]
    conn.close()
    isowner = name == owner
    return isowner


def admin_statistics():
    conn = sqlite3.connect(database)
    c = conn.cursor()
    users = c.execute("SELECT * FROM users").fetchall()
    categories = c.execute("SELECT * FROM category").fetchall()
    docs = c.execute("SELECT * FROM docs").fetchall()
    users = len(users)
    categories = len(categories)
    docs = len(docs)
    dbsizekb = os.stat(database).st_size
    dbsizemb = float(dbsizekb) / 1024 / 1024
    dbsizemb = round(dbsizemb, 2)
    get_uploadsize()
    return users, categories, docs, dbsizekb, dbsizemb


def get_uploadsize():
    size = 0
    folderpath = os.path.join(basedir)

    for path, dirs, files in os.walk(folderpath):
        for f in files:
            fp = os.path.join(path, f)
            size += os.path.getsize(fp)
    sizebytes = size
    sizemb = float(size) / 1024 / 1024
    sizemb = round(sizemb, 3)
    sizegb = float(size) / 1024 / 1024 / 1024
    sizegb = round(sizegb, 3)

    return sizebytes, sizemb, sizegb


def check_permissions(filename):
    # ist der Benutzer der Besitzer oder admin?

    if 'name' not in session:
        flash("Sie müssen sich erst einloggen!")
        time.sleep(1)
        return redirect(url_for("index"))

    conn = sqlite3.connect(database)
    c = conn.cursor()
    params = (filename, )
    sql = """SELECT owner FROM docs WHERE filename IS ?"""
    owner = c.execute(sql, params).fetchone()
    owner = owner[0]
    name = session["name"]
    c.close()
    admin = is_admin()

    if admin:
        permission = True

    if not admin:
        permission = owner == name


    return permission


def is_private(filename):
    # Prüfung ob Dokument privat
    conn = sqlite3.connect(database)
    c = conn.cursor()
    params = (filename,)
    sql = """SELECT private FROM docs WHERE filename IS ?"""
    private = c.execute(sql, params).fetchone()
    if private == 0:
        private = False
    else:
        private = True

    return private

if __name__ == "__main__":
    app.run(debug=True)  # bei Produktivsystemen mus das debugging auf False gesetzt werden.
