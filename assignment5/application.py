import json
import logging
from logging.config import dictConfig
import os
from pathlib import Path
import secrets

import bcrypt
from flask import Flask, Response, abort, redirect, render_template, request, session, url_for
from google.auth.exceptions import GoogleAuthError
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.errors import HttpError
from oauthlib.oauth2 import OAuth2Error
from requests.exceptions import RequestException
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.utils import secure_filename

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = Path(__file__).with_name("google_oauth_client_secret.json")



# Request the Google account email address.
SCOPES = ['https://www.googleapis.com/auth/userinfo.email']
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'


dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    },
     'file.handler': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'photoportal.log',
            'maxBytes': 10000000,
            'backupCount': 5,
            'level': 'INFO',
        },
    },
    'root': {
        'level': 'INFO',
        'handlers': ['file.handler']
    }
})

PHOTO_FOLDER = "static/images/photos"


app = Flask(__name__)

app.secret_key = os.getenv("PHOTO_PORTAL_SECRET_KEY") or secrets.token_hex()
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax")

# Ref: https://stackoverflow.com/questions/14888799/disable-console-messages-in-flask-server
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# SQLite Database creation
Base = declarative_base()

db_name = os.getenv("PHOTO_PORTAL_DB","photosdata.db")
db_url = "sqlite:///" + db_name
engine = create_engine(db_url, future=True, connect_args={'check_same_thread': False})

DBSession = sessionmaker(bind=engine)

# Class that represents Database table "PhotoData"
class PhotoData(Base):
    __tablename__ = 'photos'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    date_taken = Column(String)
    tags = Column(String)

    def __repr__(self):
        return "<PhotoData(name='%s', date_taken='%s', tags='%s')>" % (
                self.name, self.date_taken, self.tags)

    # Ref: https://stackoverflow.com/questions/5022066/how-to-serialize-sqlalchemy-result-to-json
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    user_type = Column(String, nullable=False)

    def as_dict(self):
        return {"id": self.id, "name": self.name, "user_type": self.user_type}


# Class that represents in-memory representation of a photo
class Photo():
	def __init__(self, photo_name='', date_taken='', tags=''):
		self.name = photo_name
		self.date_taken = date_taken
		self.tags = tags


Base.metadata.create_all(engine)


# This method queries photos from the database and loads them in as in-memory list.
def load_photos():
    session = DBSession()
    photo_list = session.query(PhotoData)
    photos = []
    for photo in photo_list:
        found = False
        for p in photos:
            if p.name == photo.name:
                found = True

        if not found:
            photo = Photo(photo_name=photo.name, 
                          date_taken=photo.date_taken,
                          tags=photo.tags)
            photos.append(photo)

    return photos


def get_user_info(credentials):
    service = googleapiclient.discovery.build(
        "oauth2", "v2", credentials=credentials, cache_discovery=False
    )
    return service.userinfo().get().execute()


@app.before_request
def check_photo_access():
    role = session.get("user_type")
    if request.endpoint in {"upload_photo", "update_tags", "delete_photos"}:
        if role != "admin":
            abort(403)
    viewing_photo = request.endpoint in {"get_photos", "get_tags_for_photo", "search"}
    if request.endpoint == "static":
        viewing_photo = request.view_args["filename"].startswith("images/photos/")
    if viewing_photo and role not in {"admin", "general"}:
        abort(403)


@app.route("/users", methods=["POST"])
def add_user():
    # Bootstrap on the server without opening admin registration to the public.
    if request.remote_addr not in {"127.0.0.1", "::1"} and session.get("user_type") != "admin":
        abort(403)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("user_type") != "admin":
        return Response("Expected an admin user.\n", status=400)
    name = data.get("name")
    password = data.get("password")
    if not isinstance(name, str) or not name.strip() or not isinstance(password, str):
        return Response("Name and password are required.\n", status=400)
    name = name.strip()
    password_bytes = password.encode("utf-8")
    if not 1 <= len(password_bytes) <= 72:
        return Response("Password must be 1 to 72 bytes.\n", status=400)
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("ascii")
    with DBSession() as db:
        db.add(User(name=name, password=hashed, user_type="admin"))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return Response(f"User with name {name} already exists.\n", status=400)
    return {"name": name, "user_type": "admin"}


@app.route("/users", methods=["GET"])
def get_users():
    with DBSession() as db:
        return {"users": [user.as_dict() for user in db.query(User).order_by(User.id)]}


# REST API to get photos - Sends photo names back
@app.route("/photos", methods=["GET"])
def get_photos():

    photos = load_photos()
    photo_json_list = []
    for photo in photos:
        photo_json_list.append(json.dumps(photo.__dict__))

    ret_obj = {}
    ret_obj["photos"] = photo_json_list
    return ret_obj


@app.route("/photos/<photo>/tags")
def get_tags_for_photo(photo):
    app.logger.info("Inside get_tags_for_photo:" + photo)

    tags_to_return = ""
    dbsession = DBSession()
    photo_obj = dbsession.query(PhotoData).filter_by(name=photo)
    if photo_obj.first() != None:
        photo_obj1 = photo_obj.first()
        tags_to_return = photo_obj1.tags
        app.logger.info("Tags to return:" + tags_to_return)

    ret_obj = {}
    ret_obj["tags"] = tags_to_return
    return ret_obj


@app.route("/update_tags", methods=["POST"])
def update_tags():
    app.logger.info("Inside update_tags")

    photo_name = request.form["photo_name_for_tags_update"].strip()
    app.logger.info("Photo:" + photo_name)

    new_tags = request.form["new_tags"].strip()
    app.logger.info("New tags:" + new_tags)

    dbsession = DBSession()
    photo = dbsession.query(PhotoData).filter_by(name=photo_name).first()
    photo.tags = new_tags # new_tags should be overwritten - this is okay as we are first retrieving existing tags;
    dbsession.commit()

    username = ""
    if "username" in session:
        username = session['username']

    upload_form_display="display:block;"
    slide_show_display="display:block;" 

    photos = load_photos()

    tag_update_status = "Tags successfully updated for:" + photo_name

    return render_template("photo-portal.html",
                            username=username,
                            upload_form_display=upload_form_display,
                            slide_show_display=slide_show_display,
                            photo_upload_status=tag_update_status,
                            photo_list=photos,
                            user="admin")


@app.route("/delete_photos", methods=["POST"])
def delete_photos():
    app.logger.info("Inside delete_photos.")
    dbsession = DBSession()
    selected_photos = request.form.getlist("photos_to_update_delete")
    final_status = ""
    for name in selected_photos:
        app.logger.info("Photo to delete:" + name)
        photo = dbsession.query(PhotoData).filter_by(name=name).first()

        if photo == None:
            status = ("Photo with name {name} not found.\n").format(name=name)
        else:
            app.logger.info("Found Photo:%s\n", str(photo))
            # Delete from the filesystem
            file_path = PHOTO_FOLDER + "/" + name
            if os.path.exists(file_path):
                os.remove(file_path)

            # Delete from the DB
            dbsession.delete(photo)
            dbsession.commit()
            status = ("Photo with name {name} deleted.\n").format(name=name)
            final_status = final_status + status

    username = ""
    if "username" in session:
        username = session['username']

    upload_form_display="display:block;"
    slide_show_display="display:block;" 

    photos = load_photos()

    return render_template("photo-portal.html",
                            username=username,
                            upload_form_display=upload_form_display,
                            slide_show_display=slide_show_display,
                            photo_upload_status=final_status,
                            photo_list=photos,
                            user="admin")



@app.route("/search", methods=["POST"])
def search():
	app.logger.info("Inside search")

	photos = load_photos()

	search_criteria = request.form["search_select"].strip()
	app.logger.info("Search criteria:" + search_criteria)

	search_data = request.form["search_input"].strip()
	app.logger.info("Search data:" + search_data)

	username = ""
	if "username" in session:
		username = session['username']

	matching_photos = []
	for photo in photos:
		if search_criteria == "Name":
			if search_data in photo.name:
				matching_photos.append(photo)
		if search_criteria == "Date":
			if search_data == photo.date_taken:
				matching_photos.append(photo)
		if search_criteria == "Tags":
			if search_data in photo.tags:
				matching_photos.append(photo)


	app.logger.info("Matching photos:")
	app.logger.info(matching_photos)

	if len(matching_photos) > 0:
		status = "Matching photos found."
	else:
		status = "No matching photos found."

	upload_form_display="display:block;"
	slide_show_display="display:none;"
	type_of_user = "admin"
	if session.get("user_type") == "general":
		upload_form_display="display:none;"
		slide_show_display="display:block;" 
		type_of_user = "general"

	return render_template("photo-portal.html",
							username=username,
							upload_form_display=upload_form_display,
							slide_show_display=slide_show_display,
							photo_upload_status=status,
							photo_list=matching_photos,
							user=type_of_user)


@app.route("/upload", methods=["POST"])
def upload_photo():
	app.logger.info("Inside upload_photo")

	username = ""
	if "username" in session:
		username = session['username']

	date_taken = request.form["date_taken"].strip()
	tags = request.form["tags"].strip()
	file = request.files['photo_name']
	filename = secure_filename(file.filename)
	filename = filename.strip()
	app.logger.info("File Name:%s\n", filename)
	app.logger.info("Date taken:" + date_taken)
	app.logger.info("Tags:" + tags)

	if not filename or Path(filename).suffix.lower() not in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".avif", ".tif", ".tiff"}:
		abort(400, "Choose a supported image file.")

	photo_data = PhotoData(name=filename, date_taken=date_taken, tags=tags)

    # First query to find out if a photo with the name already exists.
    # Commit the photo only if photo with the name does not exist.
	dbsession = DBSession()
	photo_obj = dbsession.query(PhotoData).filter_by(name=filename).first()
	if photo_obj is None:
		os.makedirs(PHOTO_FOLDER, exist_ok=True)
		file.save(PHOTO_FOLDER + "/" + filename)
		status = "Photo " + filename + " uploaded successfully."
		dbsession.add(photo_data)
		dbsession.commit()
	else:
		status = "Photo " + filename + " already exists."

	photos = load_photos()

	slide_show_display = "display:block"

	return render_template("photo-portal.html",
							username=username,
							photo_upload_status=status,
							slide_show_display=slide_show_display,
							photo_list=photos,
                            user="admin")


def oauth_flow(state=None):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
    )
    flow.redirect_uri = os.getenv("PHOTO_PORTAL_OAUTH_REDIRECT_URI") or url_for(
        "oauth2callback", _external=True
    )
    return flow


@app.route("/login_with_google", methods=["GET", "POST"])
def authorize():
    if not os.path.exists(CLIENT_SECRETS_FILE):
        return render_template("google-oauth-client-secrets-file-missing.html"), 503
    flow = oauth_flow()
    authorization_url, state = flow.authorization_url()
    session["oauth_state"] = state
    session["oauth_code_verifier"] = flow.code_verifier
    return redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    state = session.pop("oauth_state", None)
    code_verifier = session.pop("oauth_code_verifier", None)
    if not state or not secrets.compare_digest(
        state.encode("utf-8"), request.args.get("state", "").encode("utf-8")
    ):
        return render_template("index.html", error="Google sign-in session expired. Please try again."), 400
    if request.args.get("error") or not request.args.get("code"):
        return render_template("index.html", error="Google sign-in was not completed."), 400

    try:
        flow = oauth_flow(state)
        flow.code_verifier = code_verifier
        flow.fetch_token(code=request.args["code"])
        profile = get_user_info(flow.credentials)
    except (OAuth2Error, RequestException, GoogleAuthError, HttpError, OSError, ValueError):
        return render_template("index.html", error="Google sign-in failed. Please try again."), 502

    email = profile.get("email")
    if not email or not profile.get("verified_email"):
        return render_template("index.html", error="Google did not provide a verified email."), 403
    email = email.strip().lower()

    with DBSession() as db:
        db.execute(
            insert(User).values(name=email, password="", user_type="general")
            .on_conflict_do_nothing(index_elements=["name"])
        )
        user = db.query(User).filter_by(name=email).one()
        if user.user_type != "general":
            return render_template("index.html", error="That email is already registered as an admin."), 409
        db.commit()

    session.clear()
    session.update(username=email, user_type="general")
    return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
def logout():
    role = session.get("user_type")
    session.clear()
    return redirect(url_for("adminindex" if role == "admin" else "index"))


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").encode("utf-8")
        with DBSession() as db:
            user = db.query(User).filter_by(name=username, user_type="admin").first()
            if user is None:
                return render_template("adminindex.html", error=f"{username} not found"), 404
            stored_hash = user.password
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode("ascii")
        if len(password) > 72 or not bcrypt.checkpw(password, stored_hash):
            return render_template("adminindex.html", error="password does not match"), 400
        session.clear()
        session.update(username=username, user_type="admin")
        return redirect(url_for("login"))

    user_type = session.get("user_type")
    if user_type not in {"admin", "general"}:
        return redirect(url_for("index"))
    return render_template(
        "photo-portal.html",
        username=session["username"],
        upload_form_display="display:block;" if user_type == "admin" else "display:none;",
        slide_show_display="display:block;",
        photo_list=load_photos(),
        user=user_type,
    )


@app.route("/admin")
def adminindex():
    return render_template('adminindex.html')


@app.route("/")
def index():
    return render_template('index.html')


if __name__ == "__main__":

    app.debug = False
    app.logger.info('Portal started...')
    app.run(host='0.0.0.0', port=5009, ssl_context='adhoc')
