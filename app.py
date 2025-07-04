import os
import re
import time as tm
from flask import (
    Flask,
    redirect,
    url_for,
    session,
    render_template,
    request,
    flash,
    jsonify,
    Response,
    stream_with_context,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from flask_session import Session
from authlib.integrations.flask_client import OAuth
import json
import stripe
import redis
from datetime import timedelta, datetime, time
import requests
from models import db, User
from config import Config

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse, Connect, ConversationRelay
from urllib.parse import quote
import pytz
import threading

import urllib.parse

app = Flask(__name__)
app.config.from_object(Config)

user_timers = {}  # Dictionary to store user timers and data


# Redis Session Configuration
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = True  # Keep session alive after closing browser
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)  # Expire in 7 days
app.config["SESSION_USE_SIGNER"] = True  # Encrypt session cookies
app.config["SESSION_KEY_PREFIX"] = "mysession:"  # Prefix for Redis keys
redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")


app.config["SESSION_REDIS"] = redis.from_url(redis_url, decode_responses=False)
redis_client = app.config["SESSION_REDIS"]


Session(app)

# Initialize DB and Login Manager
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# STRIPE
stripe.api_key = Config.STRIPE_SECRET_KEY

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
discovery_doc = requests.get(GOOGLE_DISCOVERY_URL).json()


oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=Config.GOOGLE_CLIENT_ID,
    client_secret=Config.GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params={
        "access_type": "offline",  # Request offline access for refresh_token
        "prompt": "consent",  # Force consent to ensure refresh_token / take off if u dont want consent to pop on every login
    },
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    refresh_token_url="https://oauth2.googleapis.com/token",  # For token refreshing
    redirect_uri="https://localhost:9000/login/callback",
    client_kwargs={"scope": " ".join(Config.GOOGLE_OAUTH_SCOPES)},
    jwks_uri=discovery_doc["jwks_uri"],
)


# Store calls data
def store_call_for_user(
    user_id, phone, order_id, status, max_calls=50, ttl_seconds=3600
):
    key = f"user:{user_id}:calls"
    call_data = {
        "phone": phone,
        "order_id": order_id,
        "status": status,
        "timestamp": tm.strftime("%Y-%m-%d %H:%M"),
    }

    redis_client.lpush(key, json.dumps(call_data))
    redis_client.ltrim(key, 0, max_calls - 1)
    redis_client.expire(key, ttl_seconds)


# HELPER FUNCTIONS
def get_user_by_email(email):
    user = User.query.filter_by(email=email).first()
    return user


def format_datetime(iso_string):
    # Parse the input string
    dt = datetime.fromisoformat(iso_string)

    # Convert to local time zone if needed (optional)
    local_tz = pytz.timezone("Europe/Athens")  # Adjust timezone as needed
    dt = dt.astimezone(local_tz)

    # Format in a more human-readable way
    return dt.strftime("%A, %B %d, %Y at %I:%M %p %Z")


def handle_subscription_update(subscription):
    """Update the user's subscription status based on Stripe data."""
    user = User.query.filter_by(stripe_customer_id=subscription["customer"]).first()
    print(User.query.filter_by(stripe_customer_id=subscription["customer"]))
    if user:
        user.subscription_status = (
            "active" if subscription["status"] == "active" else "inactive"
        )
        db.session.commit()
        print("SUBSCRIPTION UPDATED")


def handle_subscription_canceled(subscription):
    """Deactivate subscription when a user cancels."""
    user = User.query.filter_by(stripe_customer_id=subscription["customer"]).first()
    print(User.query.filter_by(stripe_customer_id=subscription["customer"]))
    if user:
        user.subscription_status = "inactive"
        db.session.commit()
        print("SUBSCRIPTION CANCELED")


# Format Lists
def format_phone_number(phone):
    digits = re.sub(r"\D", "", phone)  # Remove non-digit characters
    if len(digits) == 9:
        return f"+40{digits}"
    elif len(digits) == 10 and digits.startswith("0"):
        return f"+4{digits}"
    elif len(digits) == 11 and digits.startswith("40"):
        return f"+{digits}"
    elif len(digits) == 12 and digits.startswith("40"):
        return f"+4{digits[2:]}"
    return None  # Invalid format


def extract_phone_number(note_attributes):
    phone_pattern = re.compile(
        r"(\+?\d{1,3}[-.\s]?)?(\(?\d{2,4}\)?[-.\s]?)?(\d{3,4}[-.\s]?\d{3,4})"
    )

    for item in note_attributes:
        value = item.get("value", "")
        if phone_pattern.fullmatch(
            value.replace(" ", "").replace("-", "").replace(".", "")
        ):
            return value

    return None  # Return None if no phone number found


def extract_address(note_attributes):
    address = ""
    city = ""
    county = ""

    for item in note_attributes:
        name = item.get("name", "")
        value = item.get("value", "")

        if name in [
            "Adresă",
            "Adresa",
            "Adresă livrare",
            "Address",
            "Adresa livrare",
            "Adresă Livrare",
            "Adresa Livrare",
        ]:
            address = value

        elif name in ["Localitate", "Oras", "Oraș", "Sat", "Comună", "City"]:
            city = value

        elif name in ["Județ", "Sector", "Province"]:
            county = value

    # Only join non-empty parts
    parts = [part for part in [county, city, address] if part]
    return ", ".join(parts)


def clean_order_list(order_list):
    phone_map = {}

    for order in order_list:
        formatted_phone = order["phone"]

        if not formatted_phone:
            continue  # Skip invalid phone numbers

        if not order["order_id"].startswith("#D"):
            continue  # Keep only orders with #D prefix

        order["phone"] = formatted_phone
        if formatted_phone in phone_map:
            existing_order = phone_map[formatted_phone]
            if len(order["address"]) > len(existing_order["address"]):
                phone_map[formatted_phone] = (
                    order  # Keep the order with more address info
                )
        else:
            phone_map[formatted_phone] = order

    return list(phone_map.values())


def is_within_24_hours(date_string):
    """
    Checks if a given ISO 8601 date string is within the last 24 hours.

    Args:
        date_string (str): The date string in ISO 8601 format.

    Returns:
        bool: True if the date is within the last 24 hours, False otherwise.
    """
    try:
        # Parse the date string
        date_object = datetime.fromisoformat(date_string)

        # Get the current time
        now = datetime.now(
            date_object.tzinfo
        )  # use the timezone of the date_object to avoid timezone issues.

        # Calculate the difference
        time_difference = now - date_object

        # Check if the difference is less than 24 hours
        return time_difference < timedelta(days=1)

    except ValueError:
        print("Invalid date string format.")
        return False


def is_time_within_intervals(time_intervals):
    """
    Checks if the current system time is within any of the given time intervals.

    Args:
        time_intervals (list of tuples): A list of time interval tuples,
    where each tuple contains two strings
    representing the start and end times
    in "HH:MM" format.

    Returns:
        bool: True if the current time is within any of the intervals, False otherwise.
    """
    current_time = datetime.now().time()

    for start_time_str, end_time_str in time_intervals:
        try:
            start_time = time.fromisoformat(start_time_str)
            end_time = time.fromisoformat(end_time_str)

            # Handle cases where the interval crosses midnight
            if start_time <= end_time:
                if start_time <= current_time <= end_time:
                    return True
            else:
                if current_time >= start_time or current_time <= end_time:
                    return True

        except ValueError:
            print(
                f"Invalid time format in interval: ({start_time_str}, {end_time_str})"
            )

    return False


# GEOCODING API
def geocode_address(address: str) -> dict:
    base_url = "https://maps.googleapis.com/maps/api/geocode/json"
    api_key = Config.GEOCODING_API_KEY
    encoded_address = urllib.parse.quote(address)
    url = f"{base_url}?key={api_key}&address={encoded_address}"

    response = requests.get(url)
    if response.status_code != 200:
        return {
            "status": "ERROR",
            "message": "Request failed",
            "code": response.status_code,
        }

    data = response.json()
    if not data.get("results"):
        return {"status": "NOT_FOUND", "match_type": "none"}

    result = data["results"][0]
    types = result.get("types", [])
    location_type = result.get("geometry", {}).get("location_type", "")
    partial = data.get("partial_match", False)

    if "street_address" in types and location_type == "ROOFTOP" and not partial:
        match_type = "exact"
    elif "route" in types or location_type == "GEOMETRIC_CENTER":
        match_type = "approximate"
    elif partial or "locality" in types:
        match_type = "fallback"
    else:
        match_type = "unknown"

    return {
        "status": data.get("status", "UNKNOWN"),
        "match_type": match_type,
        "formatted_address": result.get("formatted_address", ""),
        "location": result.get("geometry", {}).get("location", {}),
        "place_id": result.get("place_id", ""),
        "raw": data,  # Optional: include full response for debugging
    }


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    if current_user.is_authenticated:  # Check if user is logged in
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/policy")
def policy():
    return render_template("policy.html")


@app.route("/login")
def login():
    # Dynamically set redirect_uri based on environment
    if os.getenv("FLASK_ENV") == "development":
        redirect_uri = url_for("callback", _external=True)  # localhost
    else:
        redirect_uri = (
            "https://www.ecomdraft.online/login/callback"  # Hardcoded production URL
        )
    return google.authorize_redirect(redirect_uri)


@app.route("/login/callback")
def callback():
    token = google.authorize_access_token()

    user_info = google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()
    session["user"] = user_info

    # Enhance token
    token["token_uri"] = "https://oauth2.googleapis.com/token"
    token["client_id"] = Config.GOOGLE_CLIENT_ID
    token["client_secret"] = Config.GOOGLE_CLIENT_SECRET
    token["scopes"] = token["scope"].split(" ")

    session["google_token"] = token
    session.permanent = True
    session.modified = True

    # Check if user exists
    user = User.query.filter_by(email=user_info["email"]).first()
    if not user:
        user = User(
            google_id=user_info["id"],
            name=user_info["name"],
            email=user_info["email"],
            subscription_status="inactive",  # Default to inactive
            picture=user_info["picture"],
        )
        db.session.add(user)
    else:
        try:
            user.picture = user_info["picture"]
        except:
            pass

    db.session.commit()
    login_user(user, remember=True)

    # Check subscription status
    if user.subscription_status != "active":
        return redirect(url_for("subscribe"))

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.subscription_status != "active":
        flash("You need an active subscription to access the dashboard.", "warning")
        return redirect(url_for("subscribe"))

    if "user" not in session:
        print("Session missing 'user' key, redirecting to login")
        return redirect(url_for("login"))

    is_calling_on = user_timers.get(current_user.id, {}).get("timer", None) is not None
    profile_picture = session["user"]["picture"]
    return render_template(
        "dashboard.html",
        profile_picture=profile_picture,
        name=current_user.name,
        is_calling_on=is_calling_on,
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/subscribe")
@login_required
def subscribe():
    return render_template(
        "subscribe.html",
        subscribed=(current_user.subscription_status == "active"),
        name=current_user.name,
        profile_picture=session["user"]["picture"],
    )


# STIPE SESSION / PAYMENT MANAGEMENT
@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    try:
        # Create a Stripe Customer if the user doesn't have one
        if not current_user.stripe_customer_id:
            customer = stripe.Customer.create(email=current_user.email)
            current_user.stripe_customer_id = customer.id
            db.session.commit()

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[
                {
                    "price": "price_1QuXDOJWcRVontPNK7qYLe2o",
                    "quantity": 1,
                }
            ],
            success_url=url_for("payment_success", _external=True),
            cancel_url=url_for("subscribe", _external=True),
            customer=current_user.stripe_customer_id,  # Attach customer ID
        )
        return jsonify({"checkout_url": checkout_session.url})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/payment-success")
@login_required
def payment_success():
    # Update user's subscription status
    current_user.subscription_status = "active"
    db.session.commit()

    flash("Payment successful! Your subscription is now active.", "success")
    return redirect(url_for("dashboard"))


@app.route("/manage-subscription", methods=["POST"])
@login_required
def manage_subscription():
    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,  # Store this when creating subscriptions
            return_url=url_for(
                "dashboard", _external=True
            ),  # Redirect back after managing subscription
        )
        return jsonify({"portal_url": portal_session.url})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, Config.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    # Handle subscription events
    if event["type"] == "customer.subscription.updated":
        subscription = event["data"]["object"]
        print("Subscription updated:", subscription)

    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        print("Subscription canceled:", subscription)

    return jsonify(success=True), 200


@app.route("/get_draft_orders", methods=["GET"])
def get_draft_orders():
    if "user" not in session:
        return jsonify({"error": "User not authenticated"}), 401

    draft_orders = get_all_drafts(current_user)
    proc_drafts = process_drafts(draft_orders)

    user_email = session["user"]["email"]
    enriched_data = []
    for customer in proc_drafts:
        if customer == {}:
            continue
        if customer["phone_number"] == "" or customer["phone_number"] == None:
            continue
        try:
            customer["phone_number"] = format_phone_number(customer["phone_number"])
            status_key = f"status:{user_email}:{customer['phone_number']}"
            status = (
                (value := app.config["SESSION_REDIS"].get(status_key))
                and value.decode("utf-8")
                or "⏳"
            )
            customer["status"] = status
            enriched_data.append(customer)
        except Exception as e:
            print(f"Error at fetcing leads: {e}")
            pass
    if enriched_data == []:
        raise Exception("No data returned!")

    return jsonify({"data": enriched_data})


@app.route("/update_settings", methods=["POST"])
def update_shopify_settings():
    if "user" not in session or not current_user.is_authenticated:
        return jsonify({"error": "User not authenticated"}), 401

    data = request.get_json()
    shopify_shop_url = data.get("shopify_shop_url", "").strip()
    shopify_access_token = data.get("shopify_access_token", "").strip()
    twilio_phone_number = data.get("twilio_phone_number", "").strip()
    working_hours_start = data.get("working_hours_start", "").strip()
    working_hours_end = data.get("working_hours_end", "").strip()
    voice_message = data.get("voice_message", "").strip()
    voice_message_draft = data.get("voice_message_draft", "").strip()
    voice_gender = data.get("voice_gender", "").strip()

    if not all([shopify_shop_url, shopify_access_token, twilio_phone_number]):
        return jsonify({"error": "All fields are required"}), 400

    # Validate working hours format
    try:
        if working_hours_start and working_hours_end:
            # Convert to datetime objects to validate format
            datetime.strptime(working_hours_start, "%H:%M")
            datetime.strptime(working_hours_end, "%H:%M")
    except ValueError:
        return jsonify({"error": "Invalid time format. Please use HH:MM format"}), 400

    current_user.shopify_shop_url = shopify_shop_url
    current_user.shopify_access_token = shopify_access_token
    current_user.phone_number = twilio_phone_number
    current_user.working_hours_start = working_hours_start
    current_user.working_hours_end = working_hours_end
    current_user.voice_message = voice_message
    current_user.voice_message_draft = voice_message_draft
    current_user.agent_gender = voice_gender
    db.session.commit()
    return jsonify({"message": "Shopify settings updated"})


# TWILIO STUFF

voice_id_dic = {
    "m_1": "am5XuPVtut7uKJQKMja2",
    "m_2": "S98OhkhaxeAKHEbhoLi7",
    "m_3": "sGcPNcpR5PikknzyXcy7",
    "f_1": "urzoE6aZYmSRdFQ6215h",
    "f_2": "gbLy9ep70G3JW53cTzFC",
    "f_3": "cD1j5eDqipyIUMIi7Q5e",
}

twilio_client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN)
call_responses = {}


def init_outbound_call(
    to_phone_number,
    from_phone_number,
    user_email,
    order_id,
    order_value,
    items_list,
    confirm_address,
    formatted_address,
    type,  # can be "draft" or "order" or "demo"
    delivery_fee=0,
):
    store_url = current_user.shopify_shop_url
    call = twilio_client.calls.create(
        to=to_phone_number,
        from_=from_phone_number,
        url=f"http://37.27.108.19:9000/voice-webhook?order_id={quote(str(order_id))}&user_email={quote(str(user_email))}&order_value={quote(str(order_value))}&items_list={quote(str(items_list))}&confirm_address={quote(str(confirm_address))}&formatted_address={quote(str(formatted_address))}&type={quote(str(type))}&delivery_fee={quote(str(delivery_fee))}&store_url={quote(str(store_url))}",
    )

    print("Call initiated:", call.sid)

    return call.sid


@app.route("/demo-call", methods=["POST"])
def demo_call():
    data = request.get_json()
    to_phone_number = format_phone_number(data.get("to_phone_number"))
    confirm_address = data.get("confirm_address", "0")
    address = data.get("address", "")
    type = data.get("type", "draft")
    order_amount = data.get("order_amount", "100")
    delivery_fee = data.get("delivery_fee", "0")
    items = data.get("items", [])

    if confirm_address == True:
        confirm_address = "1"
    else:
        confirm_address = "0"

    try:
        init_outbound_call(
            to_phone_number,
            current_user.phone_number,
            current_user.email,
            "#0000",
            order_amount,
            ", ".join(items) if items else "Nume produs",
            confirm_address,
            address,
            type,
            delivery_fee,
        )
    except Exception as e:
        print(e)
        return jsonify({"error": "Failed to start demo call!"})

    return jsonify({"message": "Demo call initiated!"})


@app.route("/voice-webhook", methods=["POST"])
def voice_webhook():
    user_email = request.args.get("user_email", "")
    order_id = request.args.get("order_id", "")
    order_value = request.args.get("order_value", "").split(".")[0]
    items_list = request.args.get("items_list", "")
    type = request.args.get("type", "")
    confirm_address = request.args.get("confirm_address", "")
    formatted_address = request.args.get("formatted_address", "")
    delivery_fee = request.args.get("delivery_fee", "")
    store_url = request.args.get("store_url", "")
    user_element = get_user_by_email(user_email)

    if type == "order":
        custom_message = (
            user_element.voice_message
            if user_element and user_element.voice_message
            else "Bună ziua! Ați plasat recent o comandă pe magazinul nostru pentru suma de {order_value} lei. Puteți confirma comanda dumneavoastră?"
        )
    elif type == "draft":
        custom_message = (
            user_element.voice_message_draft
            if user_element and user_element.voice_message_draft
            else "Bună ziua! Ați încercat recent să plasați o comandă pe magazinul nostru pentru suma de {order_value} lei. Doriți să confirmați comanda dumneavoastră?"
        )

    # Format the message with the actual values
    formatted_message = custom_message.format(
        order_value=order_value, item_name=items_list
    )

    response = VoiceResponse()
    connect = Connect()
    conversation_relay = ConversationRelay(
        url="wss://www.ecomdraft.online/ws/",
        welcome_greeting=formatted_message,
        ttsProvider="ElevenLabs",
        language="ro-RO",
        voice=voice_id_dic[user_element.agent_gender],
        welcomeGreetingInterruptible=False,
        interruptible=False,
    )
    conversation_relay.parameter(name="order_id", value=order_id)
    conversation_relay.parameter(name="user_email", value=user_email)
    conversation_relay.parameter(name="type", value=type)
    conversation_relay.parameter(name="confirm_address", value=confirm_address)
    conversation_relay.parameter(name="formatted_address", value=formatted_address)
    conversation_relay.parameter(name="delivery_fee", value=delivery_fee)
    conversation_relay.parameter(name="items_list", value=items_list)
    conversation_relay.parameter(name="order_value", value=order_value)
    conversation_relay.parameter(name="store_url", value=store_url)
    conversation_relay.parameter(name="initial_message", value=formatted_message)
    connect.append(conversation_relay)

    response.append(connect)
    return Response(str(response), mimetype="text/xml")


@app.route("/call-result", methods=["POST"])
async def call_result():
    is_demo = 0
    data = request.get_json()

    call_sid = data.get("call_sid")
    to_phone_number = data.get("to_phone_number")
    user_email = data.get("user_email")
    order_id = data.get("order_id")
    type = data.get("type")
    status = data.get("status")
    new_address = data.get("new_address", "")

    # TODO: Change the address in the Shopify Order -> handled in tool calls now

    print(f"📞 Received result for user: {user_email}, order: {order_id}, type: {type}")
    print(f"✅ Outcome: {status}")
    if new_address != "":
        print(f"🏠 New address: {new_address}")
    if status == "question":
        response = {"message": "Other question", "receivedData": data}
        return jsonify(response)

    user_element = get_user_by_email(user_email)
    if (
        user_element.shopify_shop_url == None
        or user_element.shopify_access_token == None
    ):
        print(f"THE USER HAS NO SHOPIFY SETTINGS: {user_element.email}")
        return jsonify({"error": "User has not filled SHOPIFY settings!"})

    if type == "order":  # process the order confirmation status
        order = get_order_by_name(user_element, order_id)
        if not order:
            print(f"ERROR: can't get the order for order_id: {order_id}")
            return jsonify({"error": f"can't get the order for order_id: {order_id}"})
        edit_order_note(user_element, order["id"], f"called: {status}")
    elif type == "draft":  # process the draft order
        process_draft_order(user_element, order_id, status)
    else:  # mark as it being a demo call
        is_demo = 1

    if is_demo != 1:
        redis_key = f"call:{user_email}:{call_sid}"
        status_key = f"status:{user_email}:{to_phone_number}"
        app.config["SESSION_REDIS"].setex(redis_key, 300, status)
        app.config["SESSION_REDIS"].setex(status_key, 86400, status)

    response = {"message": "Data received successfully!", "receivedData": data}
    return jsonify(response)


# called by the FRONTEND to call a single draft order
@app.route("/call_draft", methods=["POST"])
def call_draft():
    if "user" not in session:
        return jsonify({"error": "User not authenticated"}), 401

    data = request.get_json()
    if not data or "phone" not in data:
        return jsonify({"error": "No phone number provided"}), 400

    phone = data["phone"]
    order_value = data.get("order_value", "necunoscută")
    order_id = data.get("order_id", "")
    item_name = data.get("item_name", "")
    address = data.get("address", "")
    user_email = session["user"]["email"]
    status_key = f"status:{user_email}:{phone}"

    # Check if already processed
    existing_status = (
        value := app.config["SESSION_REDIS"].get(status_key)
    ) and value.decode("utf-8")

    if existing_status != "No Answer" and existing_status != None:
        return jsonify({"status": existing_status, "skipped": True})

    confirm_address = 0

    geocode_response = geocode_address(address)
    if geocode_response["match_type"] != "exact":
        confirm_address = 1
    formatted_address = geocode_response["formatted_address"]

    try:
        # Call the user and get their response
        call_sid = init_outbound_call(
            phone,
            current_user.phone_number,
            user_email,
            order_id,
            order_value,
            item_name,
            confirm_address,
            formatted_address,
            "draft",
        )

        redis_key = f"call:{user_email}:{call_sid}"

        # Wait for the response (poll the call_responses store)
        timeout = 70  # Max wait time in seconds
        elapsed = 0
        interval = 1  # Check every second

        while elapsed < timeout:
            status = (
                value := app.config["SESSION_REDIS"].get(redis_key)
            ) and value.decode("utf-8")

            if status:
                app.config["SESSION_REDIS"].delete(redis_key)
                app.config["SESSION_REDIS"].setex(
                    status_key, 86400, status
                )  # Persist status
                return jsonify({"status": status})
            tm.sleep(interval)
            elapsed += interval

        # If no response within timeout, return an error
        return jsonify({"error": "No response received within timeout"}), 408

    except Exception as e:
        return jsonify({"error": f"Call failed: {str(e)}"}), 500


# SHOPIFY INTEGRATION
def get_draft_order_by_name(user_element, draft_order_name):
    """
    Get a draft order by its name (e.g., #D1003)
    """
    # Remove the # if present and ensure it's in the right format
    clean_name = draft_order_name.replace("#", "")

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }
    # Get all draft orders
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-04"
    url = f"{base_url}/draft_orders.json"
    response = requests.get(url=url, headers=headers, verify="/app/cacert.pem")

    if response.status_code == 200:
        draft_orders = response.json()["draft_orders"]

        # Find the draft order with the matching name
        for draft_order in draft_orders:
            # Draft order names are usually in the format #D1003
            if draft_order["name"].replace("#", "") == clean_name:
                return draft_order

        print(f"Draft order {draft_order_name} not found.")
        return None
    else:
        print(f"Failed to retrieve draft orders. Status code: {response.status_code}")
        return None


def get_order_by_name(user_element, draft_order_name):
    """
    Get an order by its name (e.g., #1003)
    """
    # Remove the # if present and ensure it's in the right format
    clean_name = draft_order_name.replace("#", "")

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }
    # Get all orders
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-04"
    url = f"{base_url}/orders.json"
    response = requests.get(url=url, headers=headers, verify="/app/cacert.pem")

    if response.status_code == 200:
        orders = response.json()["orders"]

    else:
        print(f"Failed to retrieve orders. Status code: {response.status_code}")
        return None

    # Find the draft order with the matching name
    for order in orders:
        # Draft order names are usually in the format #D1003
        if order["name"].replace("#", "") == clean_name:
            return order

    print(f"order {draft_order_name} not found.")
    return None


def complete_draft_order(user_element, draft_order_id):
    """
    Complete a draft order, converting it to a normal order
    """
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-04"
    url = f"{base_url}/draft_orders/{draft_order_id}/complete.json?paymentpending=true"

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }
    response = requests.put(url=url, headers=headers, verify="/app/cacert.pem")

    if response.status_code == 200:
        completed_order = response.json()["draft_order"]
        print(
            f"Draft order {completed_order['name']} has been successfully converted to order {completed_order['order_id']}."
        )
        return completed_order
    else:
        print(f"Failed to complete draft order. Status code: {response.status_code}")
        return None


def delete_draft_order(user_element, draft_order_id):
    """
    Delete (cancel) a draft order
    """
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-04"
    url = f"{base_url}/draft_orders/{draft_order_id}.json"
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }
    response = requests.delete(url=url, headers=headers, verify="/app/cacert.pem")

    if response.status_code == 200:
        print(
            f"Draft order {draft_order_id} has been successfully deleted (cancelled)."
        )
        return True
    else:
        print(f"Failed to delete draft order. Status code: {response.status_code}")
        return False


def process_draft_order(user_element, draft_order_name, action):
    """
    Process a draft order: either confirm or cancel it
    """
    # Get the draft order
    draft_order = get_draft_order_by_name(user_element, draft_order_name)

    if not draft_order:
        return

    draft_order_id = draft_order["id"]

    if action.lower() == "confirm":
        # Complete the draft order
        complete_draft_order(user_element, draft_order_id)
    elif action.lower() == "cancel":
        # Delete the draft order
        delete_draft_order(user_element, draft_order_id)
    else:
        print("Invalid action. Please use 'confirm' or 'cancel'.")


def get_all_drafts(user_element):
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }
    # Get all draft orders
    url = (
        "https://"
        + user_element.shopify_shop_url
        + "/admin/api/2025-04/draft_orders.json"
    )
    response = requests.get(url=url, headers=headers, verify="/app/cacert.pem")

    if response.status_code == 200:
        draft_orders = response.json()["draft_orders"]

        return draft_orders
    else:
        print(f"Failed to retrieve draft orders. Status code: {response.status_code}")
        return None


def process_drafts(draft_orders):
    drafts = []
    for draft_order in draft_orders:
        if draft_order.get("status", "") != "open":
            continue
        if draft_order.get("tags", "") == "abandoned_checkout_releasit_cod_form":
            order_details = {}
            order_details["total_price"] = draft_order.get("total_price", "")
            order_details["order_name"] = draft_order.get("name", "")
            try:
                order_details["item_name"] = draft_order["line_items"][0]["name"]
            except:
                order_details["item_name"] = ""
            try:
                order_details["address"] = extract_address(
                    draft_order.get("note_attributes")
                )
            except Exception as e:
                print(f"cant get draft order details:\n{e}")
            order_details["created_at"] = format_datetime(
                draft_order.get("created_at", "")
            )

            note_attributes = draft_order.get("note_attributes", "")

            if note_attributes != "" and note_attributes != []:
                phone_number = extract_phone_number(note_attributes)
            else:
                phone_number = ""

            order_details["phone_number"] = phone_number

            drafts.append(order_details)
    return drafts


def get_all_orders(user_element):
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }
    # Get all draft orders
    url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-04/orders.json"
    response = requests.get(url=url, headers=headers, verify="/app/cacert.pem")

    if response.status_code == 200:
        orders = response.json()["orders"]

        return orders
    else:
        print(f"Failed to retrieve orders. Status code: {response.status_code}")
        return None


def get_one_order(user_element, order_id):
    headers = {
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }

    response = requests.get(
        f"https://{user_element.shopify_shop_url}/admin/api/2025-04/orders/{order_id}.json",
        headers=headers,
    )
    return response.json()


def edit_order_note(user_element, order_id, note_text):
    """
    Edit the order note. If the order has no note, create a new one. If the order has a note, append the new note to the existing one.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }

    order_object = get_one_order(user_element, order_id)
    existing_note = order_object["order"]["note"]
    if existing_note == None:
        existing_note = ""

    updated_note = existing_note + "\n" + note_text

    json_data = {"order": {"id": order_id, "note": updated_note}}
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-04"
    url = f"{base_url}/orders/{order_id}.json"
    response = requests.put(url=url, headers=headers, json=json_data)

    if response.status_code == 200:
        print(response.text)

        return None
    else:
        print(
            f"Failed to Edit Order Note. Status code: {response.status_code}, {response.text}"
        )
        return None


def change_order_shipping_address_in_notes(user_element, order_id, new_address):
    headers = {
        "X-Shopify-Access-Token": user_element.shopify_access_token,
        "Content-Type": "application/json",
    }

    order_object = get_one_order(user_element, order_id)
    note_attributes = order_object["order"]["note_attributes"]
    note_attributes.append(
        {
            "name": "Adresă schimbată",
            "value": new_address,
        }
    )

    json_data = {
        "order": {
            "id": order_id,
            "note_attributes": note_attributes,
        },
    }

    response = requests.put(
        f"https://{user_element.shopify_shop_url}/admin/api/2025-04/orders/{order_id}.json",
        headers=headers,
        json=json_data,
    )

    if response.status_code == 200:
        return True
    else:
        print(
            f"Failed to change order shipping address in note attributes. Status code: {response.status_code}"
        )
        return False


def change_order_shipping_address(user_element, order_id, new_address):
    headers = {
        "X-Shopify-Access-Token": user_element.shopify_access_token,
        "Content-Type": "application/json",
    }

    json_data = {
        "order": {
            "id": int(order_id),
            "shipping_address": {
                "address1": new_address,
                "city": "Bucuresti",
            },
        },
    }

    response = requests.put(
        f"https://{user_element.shopify_shop_url}/admin/api/2025-04/orders/{order_id}.json",
        headers=headers,
        json=json_data,
    )

    if response.status_code == 200:
        return True
    else:
        print(
            f"Failed to change order shipping address. Status code: {response.status_code}"
        )
        return False


# Functions to handle tool calls in the websocket server, but need resources from the backend server
def edit_order_note_by_email(user_email, order_id, note_text):
    user_element = get_user_by_email(user_email)
    if user_element == None:
        print(f"User {user_email} not found")
        return 1
    edit_order_note(user_element, order_id, note_text)
    return 0


# Function to change the address of the order in notes and in the actual order
def change_address_by_email(user_email, order_id, new_address):
    user_element = get_user_by_email(user_email)
    if user_element == None:
        print(f"User {user_email} not found")
        return 1
    change_order_shipping_address_in_notes(user_element, order_id, new_address)
    try:
        change_order_shipping_address(user_element, order_id, new_address)
    except Exception as e:
        pass
    return 0


def get_uncalled_leads(user_element):
    """
    Gets all the leads within the last 24h
    """
    orders = get_all_orders(user_element)

    uncalled_orders = []
    for order in orders:
        if not is_within_24_hours(order["created_at"]):
            break

        if order["note"] == None or "called" not in order["note"]:
            if order.get("tags", "") == "releasit_cod_form":
                uncalled_orders.append(order)

    return uncalled_orders[::-1]


def call_all_uncalled_leads(user_element):
    if not is_time_within_intervals(
        [(user_element.working_hours_start, user_element.working_hours_end)]
    ):  # checks if we are within the working hours, else dont make the call
        print("Not within the working hours")
        return

    uncalled_leads = get_uncalled_leads(user_element)
    if uncalled_leads == [] or uncalled_leads == None:
        return

    for ul in uncalled_leads:
        try:
            confirm_address = 0
            print(f"Calling order {ul['name']} ...")
            phone_number = extract_phone_number(ul.get("note_attributes", []))
            if phone_number == None:
                continue
            full_address = extract_address(ul.get("note_attributes"))
            # Compute Address validity
            geocode_response = geocode_address(full_address)
            if geocode_response["match_type"] != "exact":
                confirm_address = 1
            formatted_address = geocode_response["formatted_address"]

            # Call the recently placed order
            call_order(
                user_element,
                phone_number,
                ul["name"],
                ul["subtotal_price"],
                ", ".join(item["name"] for item in ul["line_items"]),
                confirm_address,
                formatted_address,
            )
        except Exception as e:
            print(f"Error at calling lead (call_all_uncalled_leads): {e}")


def scan_new_orders(user_element):
    """
    Runs user_function for a specific user every 2 minutes.
    """
    my_user = User(
        id=user_element.id,
        email=user_element.email,
        name=user_element.name,
        google_id=user_element.google_id,
        subscription_status=user_element,
        stripe_customer_id=user_element.stripe_customer_id,
        picture=user_element.picture,
        shopify_shop_url=user_element.shopify_shop_url,
        shopify_access_token=user_element.shopify_access_token,
        phone_number=user_element.phone_number,
        working_hours_start=user_element.working_hours_start,
        working_hours_end=user_element.working_hours_end,
        voice_message=user_element.voice_message,
        voice_message_draft=user_element.voice_message_draft,
        agent_gender=user_element.agent_gender,
    )
    thread = threading.Thread(target=call_all_uncalled_leads, args=(my_user,))
    thread.start()
    timer = threading.Timer(120, scan_new_orders, args=(my_user,))
    timer.start()

    if user_element.id not in user_timers:
        user_timers[user_element.id] = {}

    user_timers[user_element.id]["timer"] = timer


@app.route("/start_timer", methods=["POST"])
def start_timer():
    """
    Starts the 2-minute timer for a specific user.
    """
    if (
        current_user.id not in user_timers
        or user_timers[current_user.id]["timer"] is None
    ):
        scan_new_orders(current_user)
        return jsonify({"message": f"Timer started for user {current_user.id}"}), 200
    else:
        return (
            jsonify({"message": f"Timer already running for user {current_user.id}"}),
            400,
        )


@app.route("/stop_timer", methods=["POST"])
def stop_timer():
    """
    Stops the 2-minute timer for a specific user.
    """
    if current_user.id in user_timers and user_timers[current_user.id]["timer"]:
        user_timers[current_user.id]["timer"].cancel()
        user_timers[current_user.id]["timer"] = None
        return jsonify({"message": f"Timer stopped for user {current_user.id}"}), 200
    else:
        print("returned error at STOP TIMER")
        return (
            jsonify({"message": f"Timer not running for user {current_user.id}"}),
            400,
        )


def call_order(
    user_element,
    phone,
    order_name,
    order_value,
    item_name,
    confirm_address,
    formatted_address,
):
    to_phone_number = format_phone_number(phone)
    status_key = f"status:{user_element.email}:{to_phone_number}"

    # Check if already processed
    existing_status = (
        value := app.config["SESSION_REDIS"].get(status_key)
    ) and value.decode("utf-8")

    if existing_status != "No Answer" and existing_status != None:
        print(f"status: {existing_status}, SKIPPED")
        return

    try:
        # Call the user with the placed order
        call_sid = init_outbound_call(
            to_phone_number,
            user_element.phone_number,
            user_element.email,
            order_name,
            order_value,
            item_name,
            confirm_address,
            formatted_address,
            "order",
        )

        redis_key = f"call:{user_element.email}:{call_sid}"

        # Wait for the response (poll the call_responses store)
        timeout = 70  # Max wait time in seconds
        elapsed = 0
        interval = 1  # Check every second

        while elapsed < timeout:
            status = (
                value := app.config["SESSION_REDIS"].get(redis_key)
            ) and value.decode("utf-8")

            if status:
                app.config["SESSION_REDIS"].delete(redis_key)
                app.config["SESSION_REDIS"].setex(status_key, 86400, status)
                print(f"status {status} for call with sid: {call_sid}")
                update = f"Called {to_phone_number}:order {order_name} :status {status}"
                store_call_for_user(
                    user_element.id, to_phone_number, order_name, status, 50, 172800
                )
                return
            tm.sleep(interval)
            elapsed += interval

        print("ERROR: No response received within timeout")
        return

    except Exception as e:
        print(f"ERROR: Call failed: {str(e)}")
        return


@app.route("/get_users_timer", methods=["POST"])
def get_users_timer():
    try:
        data = request.get_json()

        user_id = data["user_id"]
        try:
            timer_value = user_timers[int(user_id)]["timer"]
            if timer_value != None:
                return jsonify({"message": f"Timer ON for {user_id}"}), 200
            else:
                return jsonify({"message": f"Timer OFF for {user_id}"}), 200
        except:
            print("there is no match for user_id in timers")
            return jsonify({"message": f"Timer OFF for {user_id}"}), 200
    except:
        return jsonify({"error": "Cannot get the timer!"}), 400


@app.route("/simulate_call", methods=["POST"])
def simulate_call():
    try:
        data = request.get_json()

        phone_number = data["phone_number"]
        order_id = data["order_id"]
        status = data["status"]
        uid = data["uid"]
        ttl = data["ttl"]

        store_call_for_user(uid, phone_number, order_id, status, ttl_seconds=ttl)

        return jsonify({"message": "update updated"}), 200
    except Exception as e:
        print(e)
        return jsonify({"error": "Cannot sim call!"}), 400


@app.route("/api/calls")
@login_required
def get_user_calls():
    try:
        user_id = current_user.id
        key = f"user:{user_id}:calls"
        raw_calls = redis_client.lrange(key, 0, 49)
        calls = [
            (
                json.loads(call.decode("utf-8"))
                if isinstance(call, bytes)
                else json.loads(call)
            )
            for call in raw_calls
        ]
        return jsonify(calls)
    except Exception as e:
        print(f"Error: {e}")
        return jsonify([])


@app.route("/get_geocode", methods=["POST"])
@login_required
def geocode_endpoint():
    try:
        data = request.get_json()
        address = data.get("address")

        if not address:
            return jsonify({"error": "Address is required"}), 400

        result = geocode_address(address)
        return jsonify(
            {
                "match_type": result.get("match_type"),
                "formatted_address": result.get("formatted_address"),
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get_uncalled_leads", methods=["GET"])
@login_required
def get_uncalled_leads_api():
    if "user" not in session:
        return jsonify({"error": "User not authenticated"}), 401

    uncalled_leads = get_uncalled_leads(current_user)
    processed_leads = []

    for lead in uncalled_leads:
        try:
            phone_number = extract_phone_number(lead.get("note_attributes", []))
            if not phone_number:
                continue

            address = extract_address(lead.get("note_attributes", []))
            item_name = ", ".join(
                item.get("name", "") for item in lead.get("line_items", [])
            )

            processed_lead = {
                "order_id": lead.get("name", ""),
                "phone_number": format_phone_number(phone_number),
                "address": address,
                "item_name": item_name,
                "order_value": lead.get("subtotal_price", ""),
                "shipping_fee": lead.get("total_shipping_price_set", {})
                .get("shop_money", {})
                .get("amount", "0"),
                "created_at": format_datetime(lead.get("created_at", "")),
            }
            processed_leads.append(processed_lead)
        except Exception as e:
            print(f"Error processing lead: {e}")
            continue

    return jsonify({"data": processed_leads})


@app.route("/call_order", methods=["POST"])
@login_required
def call_order_endpoint():
    if "user" not in session:
        return jsonify({"error": "User not authenticated"}), 401

    data = request.get_json()
    if not data or "phone" not in data:
        return jsonify({"error": "No phone number provided"}), 400

    phone = data["phone"]
    order_value = data.get("order_value", "necunoscută")
    order_id = data.get("order_id", "")
    item_name = data.get("item_name", "")
    address = data.get("address", "")
    delivery_fee = data.get("delivery_fee", "0")
    user_email = session["user"]["email"]
    status_key = f"status:{user_email}:{phone}"

    # Check if already processed
    # TODO: UNCOMMENT this
    # existing_status = (
    #     value := app.config["SESSION_REDIS"].get(status_key)
    # ) and value.decode("utf-8")

    # if existing_status != "No Answer" and existing_status != None:
    #     return jsonify({"status": existing_status, "skipped": True})

    # ADDRESS VALIDATION GOOGLE API
    confirm_address = 0
    try:
        geocode_response = geocode_address(address)
        if geocode_response["match_type"] != "exact":
            confirm_address = 1
        formatted_address = geocode_response["formatted_address"]
    except Exception as e:
        print(f"Error at geocode_address: {e}")
        confirm_address = 1

    try:
        # Call the user and get their response
        call_sid = init_outbound_call(
            phone,
            current_user.phone_number,
            current_user.email,
            order_id,
            order_value,
            item_name,
            confirm_address,
            formatted_address,
            "order",
            delivery_fee,
        )

        redis_key = f"call:{user_email}:{call_sid}"

        # Wait for the response (poll the call_responses store)
        timeout = 120  # Max wait time in seconds
        elapsed = 0
        interval = 1  # Check every second

        while elapsed < timeout:
            status = (
                value := app.config["SESSION_REDIS"].get(redis_key)
            ) and value.decode("utf-8")

            if status:
                app.config["SESSION_REDIS"].delete(redis_key)
                app.config["SESSION_REDIS"].setex(
                    status_key, 86400, status
                )  # Persist status
                return jsonify({"status": status})
            tm.sleep(interval)
            elapsed += interval

        # If no response within timeout, return an error
        return jsonify({"error": "No response received within timeout"}), 408

    except Exception as e:
        return jsonify({"error": f"Call failed: {str(e)}"}), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(host="0.0.0.0", port=9000, debug=True, threaded=True)
