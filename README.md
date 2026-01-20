# HiFi Delivery Eats

A full-featured food delivery web application built with Flask.

## Features

- 🍽️ **Menu Management** - Browse and order from a diverse menu
- 🛒 **Shopping Cart** - Add items, manage quantities, apply promo codes
- 📦 **Order Tracking** - Track your orders from placement to delivery
- 👤 **User Authentication** - Secure signup/login with email verification
- 🔐 **Social Login** - Login with Google, Facebook, or Twitter
- 📊 **Admin Dashboard** - Comprehensive analytics and management tools
- 🚗 **Delivery Agent Portal** - Manage deliveries efficiently
- 📧 **Email Notifications** - Order confirmations and updates
- 📈 **Sales Analytics** - Track sales trends and top-selling items

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/SCSBalaji/Hifi_Delivery_Eats.git
   cd Hifi_Delivery_Eats
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   python download_nltk_resources.py
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. Run the application:
   ```bash
   python app.py
   ```

6. Open your browser and navigate to `http://127.0.0.1:5000`

## Deployment

For complete deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

### Quick Deploy Options

- **Render.com** (Recommended) - Free tier available
- **Heroku** - Paid plans only
- **Railway** - Limited free tier

## Project Structure

```
Hifi_Delivery_Eats/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── existing_database.db    # SQLite database
├── Procfile               # Process configuration
├── render.yaml            # Render.com configuration
├── runtime.txt            # Python version
├── static/                # Static files (CSS, JS, images)
├── templates/             # Jinja2 HTML templates
└── DEPLOYMENT.md          # Deployment guide
```

## Environment Variables

See [.env.example](.env.example) for required environment variables.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.