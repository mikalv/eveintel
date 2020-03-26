# -*- encoding: utf-8 -*-
from datetime import datetime

from esipy import EsiApp
from esipy import EsiClient
from esipy import EsiSecurity
from esipy.exceptions import APIException

from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for

from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound

import requests
import config
import hashlib
import hmac
import logging
import random
import time

# logger stuff
logger = logging.getLogger(__name__)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(formatter)
logger.addHandler(console)

# init app and load conf
app = Flask(__name__)
app.config.from_object(config)

# init db
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# init flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# -----------------------------------------------------------------------
# Database models
# -----------------------------------------------------------------------
class User(db.Model, UserMixin):
    # our ID is the character ID from EVE API
    character_id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=False
    )
    character_owner_hash = db.Column(db.String(255))
    character_name = db.Column(db.String(200))

    # SSO Token stuff
    access_token = db.Column(db.String(4096))
    access_token_expires = db.Column(db.DateTime())
    refresh_token = db.Column(db.String(100))

    def get_id(self):
        """ Required for flask-login """
        return self.character_id

    def get_sso_data(self):
        """ Little "helper" function to get formated data for esipy security
        """
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_in': (
                self.access_token_expires - datetime.utcnow()
            ).total_seconds()
        }

    def update_token(self, token_response):
        """ helper function to update token data from SSO response """
        self.access_token = token_response['access_token']
        self.access_token_expires = datetime.fromtimestamp(
            time.time() + token_response['expires_in'],
        )
        if 'refresh_token' in token_response:
            self.refresh_token = token_response['refresh_token']


# -----------------------------------------------------------------------
# Flask Login requirements
# -----------------------------------------------------------------------
@login_manager.user_loader
def load_user(character_id):
    """ Required user loader for Flask-Login """
    return User.query.get(character_id)


# -----------------------------------------------------------------------
# ESIPY Init
# -----------------------------------------------------------------------
# create the app
esiapp = EsiApp().get_latest_swagger

# init the security object
esisecurity = EsiSecurity(
    redirect_uri=config.ESI_CALLBACK,
    client_id=config.ESI_CLIENT_ID,
    secret_key=config.ESI_SECRET_KEY,
    headers={'User-Agent': config.ESI_USER_AGENT}
)

# init the client
esiclient = EsiClient(
    security=esisecurity,
    cache=None,
    headers={'User-Agent': config.ESI_USER_AGENT}
)


# -----------------------------------------------------------------------
# Login / Logout Routes
# -----------------------------------------------------------------------
def generate_token():
    """Generates a non-guessable OAuth token"""
    chars = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    rand = random.SystemRandom()
    random_string = ''.join(rand.choice(chars) for _ in range(40))
    return hmac.new(
        config.SECRET_KEY.encode('utf-8'),
        random_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


@app.route('/sso/login')
def login():
    """ this redirects the user to the EVE SSO login """
    token = generate_token()
    session['token'] = token
    return redirect(esisecurity.get_auth_uri(
        state=token,
        scopes=['esi-killmails.read_killmails.v1']
    ))


@app.route('/sso/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route('/sso/callback')
def callback():
    """ This is where the user comes after he logged in SSO """
    # get the code from the login process
    code = request.args.get('code')
    token = request.args.get('state')

    # compare the state with the saved token for CSRF check
    sess_token = session.pop('token', None)
    if sess_token is None or token is None or token != sess_token:
        return 'Login EVE Online SSO failed: Session Token Mismatch', 403

    # now we try to get tokens
    try:
        auth_response = esisecurity.auth(code)
    except APIException as e:
        return 'Login EVE Online SSO failed: %s' % e, 403

    # we get the character informations
    cdata = esisecurity.verify()

    # if the user is already authed, we log him out
    if current_user.is_authenticated:
        logout_user()

    # now we check in database, if the user exists
    # actually we'd have to also check with character_owner_hash, to be
    # sure the owner is still the same, but that's an example only...
    try:
        user = User.query.filter(
            User.character_id == cdata['sub'].split(':')[2],
        ).one()

    except NoResultFound:
        user = User()
        user.character_id = cdata['sub'].split(':')[2]

    user.character_owner_hash = cdata['owner']
    user.character_name = cdata['name']
    user.update_token(auth_response)

    # now the user is ready, so update/create it and log the user
    try:
        db.session.merge(user)
        db.session.commit()

        login_user(user)
        session.permanent = True

    except:
        logger.exception("Cannot login the user - uid: %d" % user.character_id)
        db.session.rollback()
        logout_user()

    return redirect(url_for("index"))


# -----------------------------------------------------------------------
# Index Routes
# -----------------------------------------------------------------------
@app.route('/')
def index():
    wallet = None

    # if the user is authed, get the wallet content !
    if current_user.is_authenticated:
        # give the token data to esisecurity, it will check alone
        # if the access token need some update
        esisecurity.update_token(current_user.get_sso_data())

        #op = esiapp.op['get_characters_character_id_wallet'](
        #    character_id=current_user.character_id
        #)
        #wallet = esiclient.request(op)

    return render_template('base.html', **{
        'wallet': wallet,
    })


from pprint import pprint
    

def searchapi(text,strict=False,categories='character'):
    op = esiapp.op['get_search'](
        search=text,
        strict=strict,
        categories=categories,
        datasource='tranquility',
        language='en-us'
    )
    results = esiclient.request(op)
    return results

def getpubkms(char_id):
    cache_id = getcacheprefix(char_id) + "_zkillboard"
    if checkcache(cache_id):
        return readcache(cache_id)
    else:
        r1 = requests.get("https://zkillboard.com/api/kills/characterID/%d/" % (char_id,))
        r2 = requests.get("https://zkillboard.com/api/losses/characterID/%d/" % (char_id,))
        joined_lists = r1.json() + r2.json()
        writecache(cache_id, joined_lists)
        return joined_lists

import pickle
from os import path

CACHE_DIR = path.join(path.dirname(path.realpath(__file__)), 'cache')

def getcacheprefix(char_id):
    now = datetime.now()
    return now.strftime("%Y-%m-%d_%H_") + str(char_id)

def readcache(cache_id):
    f = open(path.join(CACHE_DIR, cache_id), "r")
    data = pickle.load(f)
    f.close()
    return data

def writecache(cache_id, data):
    f = open(path.join(CACHE_DIR, cache_id), "w+")
    pickle.dump(data, f)
    f.close()

def checkcache(cache_id):
    return ( path.exists(path.join(CACHE_DIR, cache_id)) )

def getkillmails(char_id):
    cache_id = getcacheprefix(char_id) + "_killmails"
    if checkcache(cache_id):
        return readcache(cache_id)
    else:
        data = getkillmails_nocache(char_id)
        writecache(cache_id, data)
        return data

def getkillmails_nocache(char_id):
    if current_user.is_authenticated:
        esisecurity.update_token(current_user.get_sso_data())
        token = current_user.access_token
        #op = esiapp.op['get_characters_character_id_killmails_recent'](
        #    character_id=char_id,
        #    datasource='tranquility',
        #    token=token,
        #)
        #data = esiclient.request(op)
        #pprint(data.data)

        kms = []
        systems = []
        ships = []
        data = getpubkms(char_id)

        for km in data:
            killmail_id = km['killmail_id']
            killmail_hash = km['zkb']['hash']
            killmail = None
            op = esiapp.op['get_killmails_killmail_id_killmail_hash'](
                killmail_id=killmail_id,
                killmail_hash=killmail_hash,
            )
            kmdata = esiclient.request(op)
            #pprint(kmdata.data)
            try:
                victim = kmdata.data['victim']
                is_victim = victim['character_id'] == char_id
                kmd = None
                if is_victim:
                    kmd = kmdata.data['victim']
                else:
                    for attacker in kmdata.data['attackers']:
                        #pprint(attacker)
                        try:
                            if attacker['character_id'] == char_id:
                                kmd = attacker
                        except KeyError:
                            pass
                
                ship_id = kmd['ship_type_id']
                ship_names = resolvenamesfromids([ship_id, kmdata.data['solar_system_id'], ])
                ship_name = ship_names[0]['name']
                solar_system = ship_names[1]['name']
                #pprint(solar_system)
                
                ships.append(ship_name)
                systems.append(solar_system)
            except KeyError:
                pass

        return {'systems':systems, 'ships': ships}

    else:
        return []


def resolvenamesfromids(ids):
    op = esiapp.op['post_universe_names'](ids=ids,)
    data = esiclient.request(op)
    return data.data

def getcharinfo(char_id):
    data = None

    op = esiapp.op['get_characters_character_id'](
        character_id=char_id,
        datasource='tranquility',
    )
    data = esiclient.request(op)
    pprint(data.data)

    return data.data

@app.route('/searchintel')
def searchintel():
    data = None
    if current_user.is_authenticated:
        esisecurity.update_token(current_user.get_sso_data())
    
    return render_template('searchintel.html', **{
        'data': data,
    })

@app.route('/lookupresults')
def lookupresults():
    data = None
    char_id = None
    char_info = None
    killmails = []
    systems = None
    if current_user.is_authenticated:
        esisecurity.update_token(current_user.get_sso_data())

    searchstr = request.args.get('string')
    if len(searchstr) > 0:
        data = searchapi(searchstr)

        if data.data is not None:
            char_id = data.data['character'][0]
            print("character id: %s" % (char_id,))
            try:
                char_info = getcharinfo(char_id)
                try:
                    killmails = getkillmails(char_id)
                except TypeError:
                    pass
            except TypeError:
                pass

    names = resolvenamesfromids([char_info.corporation_id, char_info.alliance_id])
    corp_name = names[1]['name']
    alliance_name = names[0]['name']

    return render_template('lookupresults.html', **{
        'data': data,
        'char_id': char_id,
        'char_info': char_info,
        'systems': list(set(killmails['systems'])),
        'ships': list(set(killmails['ships'])),
        'corp_name': corp_name,
        'alliance_name': alliance_name,
    })        


if __name__ == '__main__':
    app.run(port=config.PORT, host=config.HOST)
