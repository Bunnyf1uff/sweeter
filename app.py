import os
from os.path import join,dirname
from dotenv import load_dotenv

from pymongo import MongoClient
import jwt
from datetime import datetime, timedelta
import hashlib
from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    url_for
)
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['UPLOAD_FOLDER'] = './static/profile_pics'

SECRET_KEY = 'SPARTA'

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME =  os.environ.get("DB_NAME")

client = MongoClient(MONGODB_URI)
db = client[DB_NAME]

TOKEN_KEY = 'mytoken'#ini yang kita buat di javascript tadi, jadi engga perlu sih masuk .env ini, mudah aja kok tau isinya

@app.route("/", methods=['GET'])
def home():
    token_recieve = request.cookies.get(TOKEN_KEY)#Kita ambil tokennya
    try:
        payload = jwt.decode(#nah sekarang kita decode, jadi secret_key dan algoritmanya harus sama dengan yang encode dia
            token_recieve,
            SECRET_KEY,
            algorithms=['HS256']
        )
        #Kita ambil data user, berdasarkan dari data payload kita tadi
        user_info = db.users.find_one({'username': payload.get('id')})
        #Lalu kita tanamkan datanya ke dalam halaman index.html
        return render_template('index.html', user_info=user_info)
    except jwt.ExpiredSignatureError: #Ini jika expired tokennya
        msg = 'Your token has expired'
        return redirect(url_for('login', msg=msg))
    except jwt.exceptions.DecodeError: #Ini jika gagal decodenya
        msg = 'There was a problem logging your in'
        return redirect(url_for('login', msg=msg))
    
@app.route("/login", methods=['GET'])
def login():
    msg = request.args.get('msg')
    return render_template('login.html', msg=msg)

@app.route("/user/<username>", methods=['GET'])
def user(username):
    token_recieve = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_recieve,
            SECRET_KEY,
            algorithms=['HS256']
        )
        status = username == payload.get('id')
        user_info = db.users.find_one(
            {'username': username},
            {'_id': False}
        )
        return render_template('user.html', user_info=user_info, status=status)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))
    
@app.route("/sign_in", methods=["POST"])
def sign_in():
    # Ngambil data dari AJAX
    username_receive = request.form["username_give"]
    password_receive = request.form["password_give"]

    #Kita enkripsikan passwordnya. Nah kenapa?
    pw_hash = hashlib.sha256(password_receive.encode("utf-8")).hexdigest()
    result = db.users.find_one( #karena di db.users.find_one
        {
            "username": username_receive,
            "password": pw_hash, #yang dicocokkan adalah password yang sudah ter enkripsi

            #Kalau kita enkripsi 'testing123'
            #Hasilnya akan seperti ini 'b822f1cd2dcfc685b47e83e3980289fd5d8e3ff3a82def24d7d1d68bb272eb32'
            #Tapi kalau beda seperti 'testing456', hasil enkripsinya beda
            #Kalau kita enkripsikan 'testing123' lagi, hasilnya tetap akan menjadi
            #'b822f1cd2dcfc685b47e83e3980289fd5d8e3ff3a82def24d7d1d68bb272eb32'
            #Yang dicari mongoDB itu yang string tak karuan di atas itu, bukan password aslinya,
            #Makanya harus kita enkripsi lagi saat di route login
        }
    )
    if result:#Ini maksudnya jika ada hasilnya, atau ketemu
        payload = {#Kita buat 'payload' atau object atau variabel untuk usernya
            "id": username_receive, #Isinya username
            # the token will be valid for 24 hours
            "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24),#ini 24 jam
            #dan juga 'signature' atau expired tokennya,
            # kalau kyk ig atau twitter gitu dia ngga make exp dong bang? soalnya tetep auto logged in
            # Kalau soal app atau aplikasi mobilenya saya kurang tahu, tapi kalau browsernya, mereka pakai session
            # Nah kalau session ini dia ga main token, tapi 'token' kita disimpan sama server, bukan browser
            # ok bang
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256") #Kita buat token kita
        #kita Enkripsikan payload kita biar tidak mudah di hack
        #payload = datanya
        #SECRET_KEY = kata kunci dari pengacakannya
        #algorithm = algoritma pengacakannya

        return jsonify(
            {
                "result": "success",
                "token": token, #Kita kirim token balik ke client(browser)
            }
        )
    # Let's also handle the case where the id and
    # password combination cannot be found
    else:
        return jsonify(
            {
                "result": "fail",
                "msg": "We could not find a user with that id/password combination",
                #Nah ini kalau tidak ketemu tadi pas kita coba cari di mongoDBnya
            }
        )

@app.route("/sign_up/save", methods=["POST"])
def sign_up():
    #Ini insert ke mongoDB seperti project-project lalu
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']

    #Password hash ini kita buat password yang kita insert menjadi sebuah string yang
    #encoded atau ter enkripsi
    password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()

    #Ini untuk persiapan data tiap user
    doc = {
        "username": username_receive,                               # id
        "password": password_hash,                                  # password
        "profile_name": username_receive,                           # user's name is set to their id by default
        "profile_pic": "",                                          # profile image file name
        "profile_pic_real": "profile_pics/profile_placeholder.png", # a default profile image
        "profile_info": ""                                          # a profile description
    }
    #Lalu insert seperti biasa
    db.users.insert_one(doc)
    return jsonify({'result': 'success'})

@app.route("/sign_up/check_dup", methods=['POST'])
def check_dup():
    username_recieve = request.form.get('username_give')
    exists = bool(db.users.find_one({'username': username_recieve}))
    return jsonify({'result': 'success', 'exists': exists})

@app.route("/update_profile", methods=['POST'])
def update_profile():
    token_recieve = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_recieve,
            SECRET_KEY,
            algorithms=['HS256']
        )
        username = payload.get('id')
        name_recieve = request.form.get('name_give')
        about_recieve = request.form.get('about_give')

        new_doc = {
            'profile_name': name_recieve,
            'profile_info': about_recieve,
        }

        if 'file_give' in request.files:
            file = request.files.get('file_give')
            filename = secure_filename(file.filename)
            extension = filename.split('.')[-1]
            file_path = f'profile_pics/{username}.{extension}'
            file.save('./static/' + file_path)
            new_doc['profile_pic'] = filename
            new_doc['profile_pic_real'] = file_path

        db.users.update_one(
            {'username': username},
            {'$set': new_doc}
        )
        return jsonify({'result': 'success', 'msg': 'Your profile has been updated'})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))

@app.route("/posting", methods=['POST'])
def posting():
    token_recieve = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_recieve,
            SECRET_KEY,
            algorithms=['HS256']
        )
        user_info = db.users.find_one({'username': payload.get('id')})
        comment_recieve = request.form.get('comment_give')
        date_recieve = request.form.get('date_give')
        doc = {
            'username': user_info.get('username'),
            'profile_name': user_info.get('profile_name'),
            'profile_pic_real': user_info.get('profile_pic_real'),
            'comment': comment_recieve,
            'date': date_recieve,
        }
        db.posts.insert_one(doc)
        return jsonify({'result': 'success', 'msg': 'Posting succesful!'})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))
    
@app.route("/get_posts", methods=['GET'])
def get_posts():
    token_recieve = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_recieve,
            SECRET_KEY,
            algorithms=['HS256']
        )
        username_recieve = request.args.get('username_give')

        if username_recieve == '':
            posts = list(db.posts.find({}).sort('date', -1).limit(20))
        else:
            posts = list(db.posts.find({'username': username_recieve}).sort('date', -1).limit(20))
            
        for post in posts:
            post['_id'] = str(post['_id'])
            post['count_heart'] = db.likes.count_documents({
                'post_id': post['_id'],
                'type': 'heart',
            })
            
            post['count_star'] = db.likes.count_documents({
                'post_id': post['_id'],
                'type': 'star',
            })

            post['count_thumbsup'] = db.likes.count_documents({
                'post_id': post['_id'],
                'type': 'thumbsup',
            })
            post['heart_by_me']= bool(db.likes.find_one({
                'post_id': post['_id'],
                'type': 'heart',
                'username': payload.get('id')
            }))
            post['star_by_me']= bool(db.likes.find_one({
                'post_id': post['_id'],
                'type': 'star',
                'username': payload.get('id')
            }))
            post['thumbsup_by_me']= bool(db.likes.find_one({
                'post_id': post['_id'],
                'type': 'thumbsup',
                'username': payload.get('id')
            }))
        return jsonify({'result': 'success', 'msg': 'Successfully fetched all posts', 'posts': posts})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))

@app.route("/update_like", methods=['POST'])
def update_like():
    token_recieve = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_recieve,
            SECRET_KEY,
            algorithms=['HS256']
        )
        user_info = db.users.find_one({'username': payload.get('id')})
        post_id_recieve = request.form.get('post_id_give')
        type_recieve = request.form.get('type_give')
        action_recieve = request.form.get('action_give')
        doc = {
            'post_id': post_id_recieve,
            'username': user_info.get('username'),
            'type': type_recieve,
        }
        if action_recieve == 'like':
            db.likes.insert_one(doc)
        else:
            db.likes.delete_one(doc)
        
        count = db.likes.count_documents({
            'post_id': post_id_recieve,
            'type': type_recieve
        })

        return jsonify({'result': 'success', 'msg': 'Updated!', 'count': count})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))

@app.route("/about", methods=['GET'])
def about():
    msg = request.args.get('msg')
    return render_template('about.html', msg=msg)

@app.route("/secret", methods=['GET'])
def secret():
    token_recieve = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_recieve,
            SECRET_KEY,
            algorithms=['HS256']
        )
        user_info = db.users.find_one({'username': payload.get('id')})
        return render_template('secret.html', user_info=user_info)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        msg = 'You need to be login to access secret page'
        return redirect(url_for('about', msg=msg))

    
if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)