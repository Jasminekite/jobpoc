import pathlib
import connexion
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

basedir = pathlib.Path(__file__).parent.resolve()
connex_app = connexion.App(__name__, specification_dir=basedir)

app = connex_app.app
app.config['SECRET_KEY'] = 'qbcdef54321'
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+pymysql://root:@localhost/kitecareer'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)
app = Flask(__name__)

