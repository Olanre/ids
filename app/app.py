
from flask import Flask, render_template, request, session, jsonify
import urllib.request
from datetime import datetime
import httpagentparser
import json
import os
import hashlib
from database import *

app = Flask(__name__)
app.secret_key = os.urandom(24)

database = "./detector.db"
conn = create_connection(database)
c = conn.cursor()

userOS = None
userIP = None
userCity = None
userBrowser = None
userCountry = None
userContinent = None
sessionID = None

def main():
    global conn, c
    
def parseVisitor(data):
    update_or_create_page(c,data)
    

@app.before_request
def getAnalyticsData():
    global userOS, userBrowser, userIP, userContinent, userCity, userCountry,sessionID 
    userInfo = httpagentparser.detect(request.headers.get('User-Agent'))
    userOS = userInfo['platform']['name']
    userBrowser = userInfo['browser']['name']
    userIP = "72.229.28.185" if request.remote_addr == '127.0.0.1' else request.remote_addr
    api = "https://www.iplocate.io/api/lookup/" + userIP
    try:
        resp = urllib.request.urlopen(api)
        result = resp.read()
        result = json.loads(result.decode("utf-8"))                                                                                                     
        userCountry = result["country"]
        userContinent = result["continent"]
        userCity = result["city"]
    except:
        print("Could not find: ", userIP)
    getSession()
    
def getSession():
    global sessionID
    time = datetime.now().replace(microsecond=0)
    if 'user' not in session:
        lines = (str(time)+userIP).encode('utf-8')
        session['user'] = hashlib.md5(lines).hexdigest()
        sessionID = session['user']
        data = [userIP, userContinent, userCountry, userCity, userOS, userBrowser, sessionID, time]
        create_session(c,data)
    else:
        sessionID = session['user']
        
@app.route('/')
def index():
    data = ['home', sessionID, str(datetime.now().replace(microsecond=0))]
    parseVisitor(data)
    return render_template('index.html')
    
@app.route('/about')
def about():
    data = ['about',sessionID, str(datetime.now().replace(microsecond=0))]
    parseVisitor(data)
    return render_template('about.html')
    
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
    
@app.route('/dashboard/<session_id>', methods=['GET'])
def sessionPages(session_id):
    result = select_all_user_visits(c,session_id)
    return render_template("dashboard-single.html",data=result)
    
@app.route('/get-all-sessions')
def get_all_sessions():
    data = []
    dbRows = select_all_sessions(c)
    for row in dbRows:
        data.append({
            'ip' : row['ip'],
            'continent' : row['continent'],
            'country' : row['country'], 
            'city' : row['city'], 
            'os' : row['os'], 
            'browser' : row['browser'], 
            'session' : row['session'],
            'time' : row['created_at']
        })
    return jsonify(data)
    
if __name__ == '__main__':
    main()
    app.run(debug=True)