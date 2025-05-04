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
    shopify_shop_url = db.Column(db.String(255))
    shopify_access_token = db.Column(db.String(255))
    phone_number = db.Column(db.String(20))
    working_hours_start = db.Column(db.String(5), default="09:00")  # Format: HH:MM
    working_hours_end = db.Column(db.String(5), default="17:00")  # Format: HH:MM
    voice_message = db.Column(
        db.String(500),
        default="Bună ziua! Ați plasat recent o comandă pe magazinul nostru pentru suma de {order_value} lei. Puteți confirma comanda dumneavoastră?",
    )
    voice_message_draft = db.Column(
        db.String(500),
        default="Bună ziua! Ați încercat recent să plasați o comandă pe magazinul nostru pentru suma de {order_value} lei. Doriți să confirmați comanda dumneavoastră?",
    )
    agent_gender = db.Column(db.String(2), default="f")
