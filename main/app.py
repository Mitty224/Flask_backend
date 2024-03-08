from flask import Flask, request, jsonify
import psycopg2
import os
import re
import sys
import jwt
import time
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from init_user_db import init_user_db
from db_friendship import init_friend_db
from init_posts_db import init_posts_db

# os.system("python3 init_user_db.py")
# os.system("python3 database_init.py")
app = Flask(__name__)
conn = psycopg2.connect(
    dbname=os.getenv('POSTGRES_DATABASE'),
    user=os.getenv('POSTGRES_USERNAME'),
    password=os.getenv('POSTGRES_PASSWORD'),
    host=os.getenv('POSTGRES_HOST'),
    port=os.getenv('POSTGRES_PORT')
)
init_user_db(conn)
init_friend_db(conn)
init_posts_db(conn)
# cur = conn.cursor()
# try:
#     cur.execute(query="SELECT * FROM bd_users;")
#     print(cur.fetchall(), file=sys.stderr)
# except Exception:
#     exit(1337)
app.config['SECRET_KEY'] = 'nigga'


@app.route('/', methods=["GET", "POST"])
def index():
    return "Bread", 200


@app.route('/api/ping', methods=['GET'])
def send():
    return jsonify({"status": "ok"}), 200


@app.route('/api/countries', methods=['GET'])
def get_countries():
    region = request.args.get('region')
    cur = conn.cursor()
    if region:
        cur.execute('SELECT * FROM countries WHERE region = %s;', (region,))
    else:
        cur.execute("SELECT * FROM countries;")
    countries = cur.fetchall()

    countries_list = []
    for country in countries:
        country_dict = {

            "name": country[1],
            "alpha2": country[2],
            'alpha3': country[3],
            'region': country[4]
        }
        countries_list.append(country_dict)

    return jsonify(countries_list), 200


@app.route('/api/countries/<string:reg>', methods=['GET'])
def get_country(reg):
    cur = conn.cursor()
    try:
        cur.execute('''
    SELECT * FROM countries
     WHERE alpha2 = UPPER(%s) OR alpha3 = UPPER(%s) OR LOWER(name) = LOWER(%s) OR LOWER(region) = LOWER(%s);
    ''', (reg, reg, reg, reg))
        country = cur.fetchone()
    except:
        return jsonify({"error": "country not found"}), 404
    if country:
        country_dict = {
            "name": country[1],
            "alpha2": country[2],
            'alpha3': country[3],
            'region': country[4]
        }
        return jsonify(country_dict), 200
    else:
        return jsonify({"error": "country not found"}), 404


#       ###############################         REGISTRATION                    ##################################
@app.route('/api/auth/register', methods=["POST"])
def register():
    cur = conn.cursor()
    login = request.json.get('login')
    if login is None:
        print("no login", file=sys.stderr)
        return jsonify("GDE MOI LOGIN SUKAAA!!!!"), 400
    email = request.json.get('email')
    if email is None:
        print("no mail", file=sys.stderr)
        return jsonify("GDE MOYA POCHTA SUKAAA!!!!"), 400
    password = request.json.get('password')
    if password is None:
        print("no pass", file=sys.stderr)
        return jsonify("GDE MOI PAROL SUKAAA!!!!"), 400
    countryCode = request.json.get('countryCode').upper()
    if countryCode is None:
        print("no countryCode", file=sys.stderr)
        return jsonify("GDE MOIYA STRANA SUKAAA!!!!"), 400
    isPublic = request.json.get('isPublic')
    if isPublic is None:
        print("no isPublic", file=sys.stderr)
        return jsonify("GDE INFA BLYYA!!"), 400
    phone = request.json.get('phone') or ""
    image = request.json.get('image') or ""

    # ############# CHECK IS ALREADY EXIST
    cur.execute('''
            SELECT email FROM bd_users WHERE email = %s;
            ''', (email,))
    if len(cur.fetchall()) != 0:
        return jsonify({"reason": "email is already used"}), 409

    cur.execute('''
            SELECT login FROM bd_users WHERE login = %s;
            ''', (login,))
    if len(cur.fetchall()) != 0:
        return jsonify({"reason": "login is already used"}), 409

    cur.execute('''
            SELECT phone FROM bd_users WHERE phone = %s;
            ''', (phone,))
    if len(cur.fetchall()) != 0:
        return jsonify({"reason": "phone is already used"}), 409

    # #######      CHECK EMAIL
    elif len(email) > 50:
        print("mail error", file=sys.stderr)
        return jsonify({'reason': 'length of email too big'}), 400


    #  ####        CHECK LOGIN
    elif len(login) >= 30:
        print("login error", file=sys.stderr)
        return jsonify({'reason': 'length of login too big'}), 400

    # ############ CHECK PASSWORD
    elif len(password) < 6 or not any(char.isupper() for char in password) \
            or not any(char.islower() for char in password) or not any(char.isdigit() for char in password):
        print("password error", file=sys.stderr)
        return jsonify({'reason': 'password is too easy'}), 400

    # ###### CHECK REG
    elif len(countryCode) >= 3:
        print("countryCode error", file=sys.stderr)
        return jsonify({'reason': 'wrong region'}), 400

    # ###### PHONE NUMBER
    elif phone != "" and not bool(re.match(r'^\+\d+$', phone)):
        print("phone error", file=sys.stderr)
        return jsonify({'reason': 'invalid phone number'}), 400
    # ####### IMAGE
    elif image != "" and len(image) > 200:
        print("image error", file=sys.stderr)
        return jsonify({'reason': 'image too big'}), 400

    # ################# IF REG SUCCESS
    else:
        cur.execute('''
            INSERT INTO bd_users (login, email, password, countryCode, isPablic, phone, image)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
            ''', (login, email, generate_password_hash(password=password),
                  countryCode, isPublic, phone, image))
        conn.commit()
        print("ura reg bil")
        user = {
            "login": login,
            "email": email,
            "countryCode": countryCode,
            "isPublic": isPublic,
            "phone": phone,
            "image": image
        }
        cur.close()
        return jsonify({'profile': dict(filter(lambda x: x[1], user.items()))}), 201


@app.route('/api/auth/sign-in', methods=['POST'])
def sign_in():
    login = request.json.get('login')
    password = request.json.get('password')
    cur = conn.cursor()
    try:
        cur.execute('SELECT password FROM bd_users WHERE login = %s;', (login,))
        user_pass = cur.fetchone()[0]
    except:
        print("incorrect login or pass")
        return jsonify({'reason': 'Incorrect login or password'}), 400
    if check_password_hash(user_pass, password):
        now = datetime.now() + timedelta(hours=24)
        timestamp = int(time.mktime(now.timetuple()) * 1000 + now.microsecond / 1000)

        token = jwt.encode({
            'user': login,
            'exp': timestamp
        }, app.config['SECRET_KEY'])

        cur.execute('UPDATE bd_users SET token = %s WHERE login = %s;', (token, login))
        conn.commit()

        return jsonify({'token': token}), 200
    else:
        print("incorrect login or pass")
        return jsonify({'reason': 'Incorrect login or password'}), 400


def token_expiration(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'reason': 'Token is missing'}), 401

        try:
            payload = jwt.decode(token.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
            now = datetime.now()
            timestamp_now = int(time.mktime(now.timetuple()) * 1000 + now.microsecond / 1000)
            if payload['exp'] < timestamp_now:
                return jsonify({'reason': 'Token has expired'}), 401
            kwargs['token'] = token.split()[1]
        except jwt.ExpiredSignatureError:
            return jsonify({'reason': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'reason': 'Invalid token'}), 401

        return func(*args, **kwargs)

    return decorated


# ################################                   PROFILE                      ##################################
# ################################                 EDIT PROFILE                   ##################################
@app.route('/api/me/profile', methods=['GET', 'PATCH'])
@token_expiration
def profile(token):
    if request.method == 'GET':
        cur = conn.cursor()
        cur.execute('SELECT * FROM bd_users WHERE token = %s;', (token,))
        user_profile = cur.fetchone()
        print("user_prof", user_profile)
        if user_profile:
            profile_data = {
                "login": user_profile[1],
                "email": user_profile[2],
                "countryCode": user_profile[4],
                "isPublic": user_profile[5],
                "phone": user_profile[6],
                "image": user_profile[7]
            }
            return jsonify(dict(filter(lambda x: x[1], profile_data.items()))), 200
        else:
            return jsonify({'reason': 'User not found'}), 401
    if request.method == 'PATCH':
        cur = conn.cursor()
        data = request.json
        if 'isPublic' in data:
            cur.execute('''UPDATE bd_users SET isPablic=%s WHERE token = %s;''', (data['isPublic'], token))

        if 'countryCode' in data and len(data['countryCode']) < 3:
            cur.execute('''UPDATE bd_users SET countryCode=%s WHERE token = %s;''', (data['countryCode'], token))

        if 'phone' in data and bool(re.match(r'^\+\d+$', data['phone'])):
            cur.execute('''UPDATE bd_users SET phone=%s WHERE token = %s;''', (data['phone'], token))

        if 'image' in data and len(data['image']) <= 200:
            cur.execute('''UPDATE bd_users SET image=%s WHERE token = %s;''', (data['image'], token))
        conn.commit()
        cur.execute('''SELECT * FROM bd_users WHERE token=%s;''', (token,))

        edited_user = cur.fetchall()
        cur.close()
        if edited_user:
            profile_data = {
                "login": edited_user[1],
                "email": edited_user[2],
                "countryCode": edited_user[4],
                "isPublic": edited_user[5],
                "phone": edited_user[6],
                "image": edited_user[7]
            }
            return jsonify(profile_data), 200
        else:
            return jsonify({'reason': 'user not found'}), 401


# ######################                  FIND PROFILE                   ##########################
@app.route('/api/profiles/<string:login>', methods=['GET'])
def get_profile(login):
    cur = conn.cursor()
    cur.execute('''SELECT isPablic FROM bd_users WHERE login=%s;''', (login,))
    idk_name = cur.fetchone()
    if idk_name == False:
        return jsonify({'reason': 'profile is private'}), 403
    elif not idk_name:
        return jsonify({'reason': 'profile not found or private'}), 401
    else:
        cur.execute('''SELECT * FROM bd_users WHERE login=%s;''', (login,))
        user_profile = cur.fetchone()
        cur.close()
        if user_profile:
            profile_data = {
                "login": user_profile[1],
                "email": user_profile[2],
                "countryCode": user_profile[4],
                "isPublic": user_profile[5],
                "phone": user_profile[6],
                "image": user_profile[7]
            }
            return jsonify(profile_data), 200
        else:
            return jsonify({'reason': 'user not found'}), 401


# ###########################                    UPDATE PASSWORD           #######################################
@app.route('/api/me/updatePassword', methods=['POST'])
@token_expiration
def updatePassword(token):
    newPassword = request.json.get('newPassword')
    oldPassword = request.json.get('oldPassword')
    cur = conn.cursor()
    cur.execute('''SELECT password FROM bd_users WHERE token=%s;''', (token,))
    passcode = cur.fetchone()[0]
    if passcode:
        if check_password_hash(passcode, newPassword):
            if not (len(newPassword) < 6 or not any(char.isupper() for char in newPassword) \
                    or not any(char.islower() for char in newPassword) or not any(
                        char.isdigit() for char in newPassword)):
                cur.execute('''UPDATE bd_users SET password=%s WHERE token = %s;''', (oldPassword, token))
                cur.execute('''UPDATE bd_users SET token = NULL
            WHERE token = %s;
            ''', (token,))
                return jsonify({'status': 'ok'}), 200
            else:
                return jsonify({'reason': 'password too easy'})
        else:
            return jsonify({'reason': 'incorrect password'})
    else:
        return jsonify({'reason': 'something, idk what kind of problem'})


#################################           FRIENDS              #######################################
# REMAKE            idk            UwU :3             pls get it
@app.route('/api/friends/add', methods=['POST'])
@token_expiration
def addFriens(token):
    cur = conn.cursor()
    login_to_add = request.json.get('login')
    cur.execute('''SELECT login FROM bd_users WHERE login = %s;''', (login_to_add,))
    friend_login = cur.fetchone()
    cur.execute('''SELECT login FROM bd_users WHERE token = %s;''', (token,))
    me = cur.fetchone()
    if me is None:
        return jsonify({'reason': 'token exp'}), 401
    else:
        me = me[0]
    if friend_login:  # Если нашелся такой пользователь
        friend_login = friend_login[0]
        if me == friend_login:  # если хочешь добавить сам себя
            return jsonify({'status': 'ok, added yourself'}), 200
        cur.execute('''SELECT * FROM friendship WHERE user_login1 = %s AND user_login2 = %s;''', (me, friend_login))
        if cur.fetchone():
            return jsonify({'status': 'ok, already exists'}, 200)
        now = datetime.now()
        cur.execute('''INSERT INTO friendship (user_login1, user_login2, timeFR) VALUES (%s, %s, %s);''',
                    (me, friend_login, now))
        conn.commit()
        return jsonify({'status': 'ok'}), 200
    else:
        return jsonify({'reason': 'not found'}), 404


# if you will try fix it. just delete and write normal code, it`s the best way
# OR you can probably fix SQL code, problems only with it
@app.route('/api/friends/remove', methods=['POST'])
@token_expiration
def removeFriend(token):
    cur = conn.cursor()
    login = request.json.get('login')
    try:
        cur.execute('''SELECT login FROM bd_users WHERE token = %s;''', (token,))
        users_friend = cur.fetchone()[0]
    except:
        cur.close()
        return jsonify({'reason': 'token exp so sorry'}), 401
    if users_friend:
        cur.execute('''SELECT * FROM friendship WHERE user_login1 = %s OR user_login2 = %s;''',
                    (users_friend, users_friend))
        friends = cur.fetchone()[0]
        if friends is None:
            return jsonify({'reason': 'token exp so sorry'}), 401
        else:
            friends = friends[0]
        if friends:
            cur.execute('''
            DELETE FROM friendship WHERE (user_login1 = %s AND user_login2 = %s)
            OR (user_login1 = %s AND user_login2 = %s);
            ''', (login, users_friend, users_friend, login))
            conn.commit()
            cur.close()
            return jsonify({'status': 'ok'}), 200
        else:
            cur.close()
            return jsonify({'status': 'ok'}), 200
    else:
        cur.close()
        return jsonify({'reason': 'token exp so sorry'}), 401


@app.route('/api/friends', methods=['GET'])
@token_expiration
def get_status(token):
    print("Got in friends")
    cur = conn.cursor()
    limit = request.args.get('limit')
    offset = request.args.get('offset')

    print(limit)
    print(offset)
    try:
        cur.execute(query=f"""SELECT login FROM bd_users WHERE token = '{token}';""")
        my_login = cur.fetchone()
    except:
        return jsonify({'reason': 'token not found'}), 401
    if not my_login:
        cur.close()
        return jsonify({'reason': 'token not found'}), 401
    my_login = my_login[0]

    cur.execute(query=f'''SELECT user_login2, timeFR FROM friendship WHERE
     user_login1 = '{my_login}' ORDER BY timeFR ASC LIMIT {limit} OFFSET {offset};
     ''')
    friends = cur.fetchone()

    return jsonify({'friends': friends}), 200


@app.route('/api/posts/new', methods=['POST'])
@token_expiration
def send_post(token):
    content = request.json.get('content')
    tags = request.json.get('tags')
    print("content", content)
    print("tags", tags)
    cur = conn.cursor()
    try:
        cur.execute(f'''SELECT login FROM bd_users WHERE token = %s;''', (token,))
        author = cur.fetchone()[0]
    except Exception as e:
        cur.close()
        print(e)
        return jsonify({'reason': 'not found'}), 401
    if author:
        now = datetime.now()
        cur.execute('''INSERT INTO posts (content, author, tags, createdAt)
         VALUES (%s, %s, %s, %s)''', (content, author, " ".join(tags), now))
        conn.commit()
        cur.execute(f'''SELECT * FROM posts WHERE author = '{author}' AND createdAt = '{now}';''')
        post = cur.fetchone()
        return_dict = {"id": str(post[0]), "content": post[1], "author": post[2], "tags": post[3].split(),
                       "createdAt": post[4].strftime("%Y-%m-%dT%H:%M:%SZ%z"), "likesCount": post[5], "dislikesCount": post[6]}
        cur.close()
        return jsonify(return_dict), 200
    else:
        cur.close()
        return jsonify({'reason': 'token exp'}), 401


@app.route('/api/posts/<string:id>')
@token_expiration
def get_post(token, id):
    cur = conn.cursor()
    try:
        cur.execute(f'''SELECT login FROM bd_users WHERE token = '{token}';''')
        user = cur.fetchone()[0]
    except Exception as e:
        print(e)
        cur.close()
        return jsonify({'reason': 'token exp'}), 401
    if user:
        cur.execute(f'''SELECT author FROM posts WHERE id = {id};''')
        author = cur.fetchone()[0]
        cur.execute(f'''SELECT isPablic FROM bd_users WHERE login = '{author}';''')
        isPublic = cur.fetchone()[0]
        if isPublic:
            cur.execute(f'''SELECT * FROM posts WHERE id = {id};''')
            post = cur.fetchone()
            return_dict = {"id": str(post[0]), "content": post[1], "author": post[2], "tags": post[3].split(),
                           "createdAt": post[4].strftime("%Y-%m-%dT%H:%M:%SZ%z"), "likesCount": post[5], "dislikesCount": post[6]}
            cur.close()
            return jsonify({'post': return_dict}), 200
        if user == author:
            cur.execute(f'''SELECT * FROM posts WHERE id = {id};''')
            post = cur.fetchone()
            return_dict = {"id": str(post[0]), "content": post[1], "author": post[2], "tags": post[3].split(),
                           "createdAt": post[4].strftime("%Y-%m-%dT%H:%M:%SZ%z"), "likesCount": post[5], "dislikesCount": post[6]}
            cur.close()
            return jsonify({'post': return_dict}), 200
        cur.execute(f'''SELECT * FROM friendship WHERE (user_login1 = {author} AND user_login2 = {user});''')
        canUserSeePost = cur.fetchone()
        if canUserSeePost:
            cur.execute(f'''SELECT * FROM posts WHERE id = {id};''')
            post = cur.fetchone()
            return_dict = {"id": str(post[0]), "content": post[1], "author": post[2], "tags": post[3].split(),
                           "createdAt": post[4].strftime("%Y-%m-%dT%H:%M:%SZ%z"), "likesCount": post[5], "dislikesCount": post[6]}
            cur.close()
            return jsonify({'post': return_dict}), 200
        else:
            cur.close()
            return jsonify({'reason': 'this is private account'}), 401
    else:
        cur.close()
        return jsonify({'reason': 'token exp'}), 401


# ######################################           10/POSTS/FEED           ###########################################
@app.route('/api/posts/feed/my', methods=['GET'])
@token_expiration
def getMyPosts(token):
    limit = request.json.get('limit')
    offset = request.json.get('offset')
    cur = conn.cursor()
    try:
        cur.execute(f'''SELECT login FROM bd_users WHERE token = {token}''')
        login = cur.fetchone()[0]
    except:
        cur.close()
        return jsonify({'reason': 'token exp'}), 401
    if login:
        cur.execute(f'''SELECT * FROM posts WHERE
     author = '{login}' ORDER BY createdAt DESC LIMIT {limit} OFFSET {offset};
     ''')
        posts = cur.fetchone()
        cur.close()
        return jsonify({'posts': posts}), 200
    else:
        cur.close()
        return jsonify({'reason': 'token exp'}), 401


@app.route('/api/posts/feed/<string:login>', methods=['GET'])
@token_expiration
def get_posts_idk(token):
    login = request.args.get('login')
    limit = request.json.get('limit')
    offset = request.json.get('offset')
    cur = conn.cursor()
    try:
        cur.execute(f'''SELECT login FROM bd_users WHERE token = {token};''')
        user = cur.fetchone()[0]
    except:
        cur.close()
        return jsonify({'reason': 'token exp'}), 401
    if user:
        cur.execute(f'''SELECT isPablic FROM bd_users WHERE login = {login};''')
        isPublic = cur.fetchone()[0]
        if isPublic:
            cur.execute(f'''SELECT * FROM posts WHERE
     author = '{login}' ORDER BY createdAt DESC LIMIT {limit} OFFSET {offset};''')
            post = cur.fetchone()
            cur.close()
            return jsonify({'post': post}), 200
        if user == login:
            cur.execute(f'''SELECT * FROM posts WHERE
     author = '{login}' ORDER BY createdAt DESC LIMIT {limit} OFFSET {offset};''')
            post = cur.fetchone()
            cur.close()
            return jsonify({'post': post}), 200
        cur.execute(f'''SELECT * FROM friendship WHERE (user_login1 = {login} AND user_login2 = {user});''')
        canUserSeePost = cur.fetchone()
        if canUserSeePost:
            cur.execute(f'''SELECT * FROM posts WHERE
     author = '{login}' ORDER BY createdAt DESC LIMIT {limit} OFFSET {offset};''')
            post = cur.fetchone()
            cur.close()
            return jsonify({'post': post}), 200
        else:
            cur.close()
            return jsonify({'reason': 'this is private account'}), 401
    else:
        cur.close()
        return jsonify({'reason': 'token exp'}), 401



if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
