from flask import Flask
from flask import render_template
from flask import request, redirect, url_for

from pymongo import Connection

import hashlib
import os

from celery import Celery

import sys
from Registry import Registry
import re

import sqlite3


def create_app():
    return Flask("ranalyzer")

app = create_app()
app.config.from_pyfile('config.py')


connection = Connection(app.config['MONGODB_SERVER'] , app.config['MONGODB_PORT'])
db = connection.ranalyzer
celery = Celery('ranalyzer', broker=app.config['BROKER_URL'] )


@celery.task
def perform_results(hash):
    print "Analyzing " + hash
    startup_checks = app.config['STARTUP_CHECKS']
    rfile = os.path.join(app.config['UPLOAD_FOLDER'], hash)
    reg = Registry.Registry(rfile)

    registry = { 'id' : hash}

    db.reg.insert(registry)

    for check in startup_checks:
        try:
            check_reg( reg, check['path'], check['key'], hash, check['regex'])
        except Registry.RegistryParse.RegistryStructureDoesNotExist:
            pass



@app.route('/upload-registry/', methods=['POST'])
def upload_file():
    file = request.files['reg']
 
    hash = hashlib.sha256()

    try:
        # FIXME: it should be saved before calculate sha256
        hash.update(file.read())
    except:
        print "Unexpected error:", sys.exc_info()
    finally:
        file.seek(0)
        hash_name = "%s" % (hash.hexdigest())
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], hash_name))
        return redirect(url_for('launch', hash=hash_name))

@app.route('/launch/<hash>/')
def launch(hash):
    perform_results.delay(hash)	
    return render_template('launch.html', hash=hash)

@app.route('/')
def index():
    return render_template('index.html')



@app.route('/view/<hash>/')
def view(hash):
    h = { "id" : hash }
    results = db.suspicious.find(h)

    suspicious = []

    for r in results:
        suspicious.append(r)

    return render_template('view.html', suspicious=suspicious)



@app.route('/list')
def list():

    regs = db.reg.find()

    analysis = []


    for r in regs:
        analysis.append(r)

    return render_template('list.html', analysis=analysis)

def check_registry_value(value, check_value, path):
    pos = value.lower().find(check_value.lower())
    if pos > 0:
        return True


def check_reg(reg, rpath, rkey, hash, regex=None):

    print "Checking " + rpath + " " + rkey 
    try:
        key = reg.open(rpath)
    except Registry.RegistryKeyNotFoundException:
        print "Couldn't find Run key. Exiting..."
        return

    if rkey == "*":
        for value in [v for v in key.values() \
                           if v.value_type() == Registry.RegSZ or \
                              v.value_type() == Registry.RegExpandSZ]:
            rkname = value.name()
            rkvalue = value.value()
            report = None

            if regex is not None:
                if re.search(regex, rkvalue):

                    startup_analysis = check_startup(rkname, rkvalue)
                    for sa in startup_analysis:
                        # FIXME: startup_analysis[0] only gets the las report
                        # FIXME: implement regex
                        crv = check_registry_value(rkvalue, sa['value'], sa['path'])
                        if crv > 0:
                            report = sa

                    data = { 'id': hash, 'path' : rpath, 'key' : rkname, 'value' : rkvalue, 'startup_analysis' : report}                    
                    db.suspicious.insert(data)
    else:
        value = key.value(rkey)
        #FIXME: check startup
        data = { 'id': hash, 'key' : value.name(), 'value' : str(value.value()) }
        db.suspicious.insert(data)        

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def check_startup(key, value):
    conn = sqlite3.connect('database.sqlite')
    conn.row_factory = dict_factory
    c = conn.cursor()
    query = "SELECT value, status, description, tested FROM pacs WHERE key LIKE '{0}'".format(key)
    results = c.execute(query)
    return results.fetchall()




if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)

