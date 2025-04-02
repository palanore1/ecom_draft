import os
import re
import time
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
from datetime import timedelta, datetime

import requests
from models import db, User
from config import Config

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse
from config import Config
from urllib.parse import quote
import pytz

app = Flask(__name__)
app.config.from_object(Config)


# Redis Session Configuration
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = True  # Keep session alive after closing browser
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)  # Expire in 7 days
app.config["SESSION_USE_SIGNER"] = True  # Encrypt session cookies
app.config["SESSION_KEY_PREFIX"] = "mysession:"  # Prefix for Redis keys
redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")


app.config["SESSION_REDIS"] = redis.from_url(redis_url, decode_responses=False)

Session(app)

# Initialize DB and Login Manager
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# STRIPE
stripe.api_key = Config.STRIPE_SECRET_KEY
STRIPE_WEBHOOK_SECRET = "whsec_OrOg0j60jZoApAgV0jlSBRNtX5zBah2n"

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
discovery_doc = requests.get(GOOGLE_DISCOVERY_URL).json()

# OAuth Setup
GOOGLE_OAUTH_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/spreadsheets.readonly",  # Sheets read access
]

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


# HELPER FUNCTIONS
def get_user_by_email(email):
    user = User.query.filter_by(email=email).first()
    return user

def format_datetime(iso_string):
    # Parse the input string
    dt = datetime.fromisoformat(iso_string)
    
    # Convert to local time zone if needed (optional)
    local_tz = pytz.timezone('Europe/Athens')  # Adjust timezone as needed
    dt = dt.astimezone(local_tz)
    
    # Format in a more human-readable way
    return dt.strftime('%A, %B %d, %Y at %I:%M %p %Z')


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


# SHEETS API
def read_google_sheet(sheet_url):
    token = session.get("google_token")

    if not token:
        return "User not authenticated."

    # print(f"token when called the get sheet: {token}")

    creds = Credentials(
        token=token["access_token"],
        refresh_token=token["refresh_token"],
        token_uri=token["token_uri"],
        client_id=token["client_id"],
        client_secret=token["client_secret"],
        scopes=token["scopes"],
    )

    service = build("sheets", "v4", credentials=creds)
    sheet_id = sheet_url.split("/d/")[1].split("/")[0]  # Extract Google Sheet ID
    range_name = "Sheet1!A1:J"  # Example range (modify as needed)

    result = (
        service.spreadsheets()
        .values()
        .get(spreadsheetId=sheet_id, range=range_name)
        .execute()
    )
    values = result.get("values", [])

    return values


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


# @app.route("/login")
# def login():
#     return google.authorize_redirect(url_for("callback", _external=True))


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
            store_name="Magazinul Nostru",
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

    profile_picture = session["user"]["picture"]
    return render_template(
        "dashboard.html",
        profile_picture=profile_picture,
        name=current_user.name,
        store_name=current_user.store_name,
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
            payload, sig_header, STRIPE_WEBHOOK_SECRET
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


@app.route("/fetch_sheet", methods=["POST"])
def fetch_sheet():
    if "user" not in session:
        return jsonify({"error": "User not authenticated"}), 401

    sheet_url = request.form.get("sheet_url")
    raw_data = read_google_sheet(sheet_url)

    if not raw_data:
        print("NO DATA FROM THE SHEETS API")
        return jsonify({"error": "No data found"}), 400

    # Manually map fields (adjust according to actual data structure)
    headers = [
        "date",
        "name",
        "phone",
        "address",
        "city",
        "item",
        "order_value",
        "discount",
        "order_id",
    ]

    data = [dict(zip(headers, row)) for row in raw_data]  # Convert each row int

    user_email = session["user"]["email"]
    enriched_data = []
    for customer in data:
        if customer == {}:
            continue
        try:
            customer["phone"] = format_phone_number(customer["phone"])
            status_key = f"status:{user_email}:{customer['phone']}"
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

    cleaned_data = clean_order_list(enriched_data)

    return jsonify({"data": cleaned_data})

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


@app.route("/update_store_name", methods=["POST"])
def update_store_name():
    if "user" not in session or not current_user.is_authenticated:
        return jsonify({"error": "User not authenticated"}), 401

    data = request.get_json()
    store_name = data.get("store_name", "").strip()
    if not store_name:
        return jsonify({"error": "Store name cannot be empty"}), 400

    current_user.store_name = store_name
    db.session.commit()
    return jsonify({"message": "Store name updated", "store_name": store_name})


@app.route("/update_settings", methods=["POST"])
def update_shopify_settings():
    if "user" not in session or not current_user.is_authenticated:
        return jsonify({"error": "User not authenticated"}), 401

    data = request.get_json()
    store_name = data.get("store_name", "").strip()
    shopify_shop_url = data.get("shopify_shop_url", "").strip()
    shopify_access_token = data.get("shopify_access_token", "").strip()
    twilio_phone_number = data.get("twilio_phone_number", "").strip()

    if not all([store_name, shopify_shop_url, shopify_access_token, twilio_phone_number]):
        return jsonify({"error": "All fields are required"}), 400

    current_user.store_name = store_name
    current_user.shopify_shop_url = shopify_shop_url
    current_user.shopify_access_token = shopify_access_token
    current_user.phone_number = twilio_phone_number
    db.session.commit()
    return jsonify({"message": "Shopify settings updated"})


# TWILIO STUFF
twilio_client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN)
call_responses = {}


def make_call(phone_number, store_name, order_value, user_email, order_id, from_number):
    """Calls the customer and plays a Romanian voice message."""
    call = twilio_client.calls.create(
        to=phone_number,
        from_=from_number,
        url=f"http://37.27.108.19:9000/voice?store_name={quote(store_name)}&order_value={quote(str(order_value))}&user_email={quote(user_email)}&order_id={quote(str(order_id))}",
    )

    print(f"📞 Calling {phone_number} - Call SID: {call.sid}")
    return call.sid


@app.route("/call_customer", methods=["POST"])
def call_customer():
    if "user" not in session:
        return jsonify({"error": "User not authenticated"}), 401

    data = request.get_json()
    if not data or "phone" not in data:
        return jsonify({"error": "No phone number provided"}), 400

    phone = data["phone"]
    store_name = data.get("store_name", "magazinul nostru")
    order_value = data.get("order_value", "necunoscută")
    order_id = data.get("order_id", "")
    user_email = session["user"]["email"]
    status_key = f"status:{user_email}:{phone}"

    # Check if already processed
    existing_status = (
        value := app.config["SESSION_REDIS"].get(status_key)
    ) and value.decode("utf-8")

    if existing_status != "No Answer" and existing_status != None:
        return jsonify({"status": existing_status, "skipped": True})

    try:
        # Call the user and get their response
        call_sid = make_call(phone, store_name, order_value, user_email, order_id, current_user.phone_number)

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
            time.sleep(interval)
            elapsed += interval

        # If no response within timeout, return an error
        return jsonify({"error": "No response received within timeout"}), 408

    except Exception as e:
        return jsonify({"error": f"Call failed: {str(e)}"}), 500


@app.route("/voice", methods=["POST"])
def voice():
    store_name = request.args.get("store_name", "magazinul nostru")
    order_value = request.args.get("order_value", "necunoscută")
    user_email = request.args.get("user_email", "")
    order_id = request.args.get("order_id", "")

    response = VoiceResponse()
    response.say(
        f"Bună ziua! Ați plasat recent o comandă pe {store_name}, pentru suma de {order_value} lei.  Puteți confirma comanda dvs.?",
        language="ro-RO",
        voice='Google.ro-RO-Wavenet-B'
    )

    process_url = (
        f"http://37.27.108.19:9000/process-response?"
        f"user_email={quote(user_email)}&order_id={quote(order_id)}"
    )

    gather = response.gather(
        input="speech",
        language="ro-RO",
        speechTimeout="auto",
        action=process_url,
        method="POST",
    )
    gather.say(
        "Spuneți 'Da' pentru confirmare sau 'Nu' pentru anulare.", language="ro-RO",voice='Google.ro-RO-Wavenet-B'
    )

    return Response(str(response), mimetype="text/xml")


@app.route("/process-response", methods=["POST"])
def process_response():
    """Processes the user's spoken response in Romanian."""
    user_response = request.form.get("SpeechResult", "").strip().lower()
    called_number = request.form.get("Called", "").strip()
    call_sid = request.form.get("CallSid", "")
    user_email = request.args.get("user_email", "")
    order_id = request.args.get("order_id", "")

    print(f"Utilizatorul a spus: {user_response}")

    response = VoiceResponse()
    status = None
    if "da" in user_response:
        response.say("Ai spus 'Da'. Mulțumim!", language="ro-RO",voice='Google.ro-RO-Wavenet-B')
        print(
            f"De salvat 'da' pt numarul: {called_number}, cu comanda {order_id}"
        )  # TODO: remove print
        user_element = get_user_by_email(user_email)
        if (
            user_element.shopify_shop_url != None
            and user_element.shopify_access_token != None
        ):
            process_draft_order(user_element, order_id, "confirm")
        status = "Confirmed"
    elif "nu" in user_response:
        response.say("Ai spus 'Nu'. Înțeles!", language="ro-RO",voice='Google.ro-RO-Wavenet-B')
        print(
            f"De salvat 'nu' pt numarul: {called_number}, cu comanda {order_id}"
        )  # TODO: remove print
        user_element = get_user_by_email(user_email)
        if (
            user_element.shopify_shop_url != None
            and user_element.shopify_access_token != None
        ):
            process_draft_order(user_element, order_id, "cancel")
        status = "Declined"
    else:
        response.say(
            "Îmi pare rău, nu am înțeles. Te rog, spune 'Da' sau 'Nu'.",
            language="ro-RO",
        )
        status = "No Answer"

    redis_key = f"call:{user_email}:{call_sid}"
    status_key = f"status:{user_email}:{called_number}"
    app.config["SESSION_REDIS"].setex(redis_key, 300, status)
    app.config["SESSION_REDIS"].setex(
        status_key, 86400, status
    )  # Store status for 24 hours

    return Response(str(response), mimetype="text/xml")


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
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-01"
    url = f"{base_url}/draft_orders.json"
    response = requests.get(url=url, headers=headers)

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


def complete_draft_order(user_element, draft_order_id):
    """
    Complete a draft order, converting it to a normal order
    """
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-01"
    url = f"{base_url}/draft_orders/{draft_order_id}/complete.json?paymentpending=true"

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }
    response = requests.put(url=url, headers=headers)

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
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-01"
    url = f"{base_url}/draft_orders/{draft_order_id}.json"
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": user_element.shopify_access_token,
    }
    response = requests.delete(url=url, headers=headers)

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
    base_url = "https://" + user_element.shopify_shop_url + "/admin/api/2025-01"
    url = f"{base_url}/draft_orders.json"
    response = requests.get(url=url, headers=headers)

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
            order_details={}
            order_details["total_price"]= draft_order.get("total_price", "")
            order_details["order_name"] = draft_order.get("name", "")
            order_details["created_at"] = format_datetime(draft_order.get("created_at", ""))

            note_attributes = draft_order.get("note_attributes", "")

            if note_attributes != "":
                for note in note_attributes:
                    if note.get("name", "") == "Phone number":
                        phone_number = note.get("value", "")
                    if note.get("name", "") == "Telefon":
                        phone_number = note.get("value", "")
            else:            
                phone_number = ""

            order_details["phone_number"] = phone_number
            
            drafts.append(order_details)
    return drafts



if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure DB is initialized

    app.run(host="0.0.0.0", port=9000, debug=False)
