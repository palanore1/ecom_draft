from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    google_id = db.Column(db.String(200), unique=True, nullable=False)
    subscription_status = db.Column(
        db.String(20), default="inactive"
    )  # active/inactive
    stripe_customer_id = db.Column(db.String(255), unique=True, nullable=True)
    picture = db.Column(db.String(255), nullable=True)
    store_name = db.Column(db.String(100), default="Magazinul Nostru")
    shopify_shop_url = db.Column(db.String(255))
    shopify_access_token = db.Column(db.String(255))
    phone_number = db.Column(db.String(20))
    cod_form_pn_label = db.Column(db.String(255), default="Phone number")
