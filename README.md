# E-commerce Integration Platform

This project is a Flask-based web application that integrates various e-commerce and communication services including Google OAuth, Stripe payments, Shopify integration, and Twilio messaging.

## Prerequisites

- Python 3.x
- Docker and Docker Compose
- Redis instance

## Environment Setup

Before running the application, you need to create a `.env` file in the root directory with the following variables:

```env
FLASK_ENV="production"

# Google OAuth credentials
GOOGLE_CLIENT_ID="your_google_client_id"
GOOGLE_CLIENT_SECRET="your_google_client_secret"

# Stripe API keys
STRIPE_PUBLIC_KEY="your_stripe_public_key"
STRIPE_SECRET_KEY="your_stripe_secret_key"

# Shopify credentials
SHOPIFY_SHOP_URL="your_shopify_shop_url"
SHOPIFY_API_KEY="your_shopify_api_key"
SHOPIFY_API_PASSWORD="your_shopify_api_password"
SHOPIFY_ACCESS_TOKEN="your_shopify_access_token"

# Twilio credentials
TWILIO_ACCOUNT_SID="your_twilio_account_sid"
TWILIO_AUTH_TOKEN="your_twilio_auth_token"
TWILIO_PHONE_NUMBER="your_twilio_phone_number"

# Redis connection URL
REDIS_URL="redis://my-redis:6379/0"
```

## Running the Application

1. Start the Redis instance using Docker Compose:
```bash
docker-compose up -d
```

2. Install the required Python packages:
```bash
pip install -r requirements.txt
```

3. Run the Flask application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Project Structure

- `app.py`: Main application file containing routes and business logic
- `models.py`: Database models and schemas
- `config.py`: Configuration settings
- `templates/`: HTML templates for the web interface
- `static/`: Static files (CSS, JavaScript, images)
- `docker-compose.yaml`: Docker Compose configuration for Redis
- `Dockerfile`: Docker configuration for the application

## Features

- Google OAuth authentication
- Stripe payment integration
- Shopify store integration
- Twilio messaging capabilities
- Redis for session management and caching

## Development

The application uses Flask as the web framework and includes various integrations for e-commerce functionality. Make sure to keep your environment variables secure and never commit them to version control.

## License

[Your License Here]
