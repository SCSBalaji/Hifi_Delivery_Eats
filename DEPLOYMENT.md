# HiFi Delivery Eats - Deployment Guide

This guide provides complete instructions for deploying the HiFi Delivery Eats application.

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Prerequisites](#prerequisites)
3. [Deployment Options](#deployment-options)
4. [Option A: Deploy on Render.com (Recommended)](#option-a-deploy-on-rendercom-recommended)
5. [Option B: Deploy on Heroku](#option-b-deploy-on-heroku)
6. [Option C: Deploy on Railway](#option-c-deploy-on-railway)
7. [Environment Variables](#environment-variables)
8. [Database Setup](#database-setup)
9. [Email Configuration](#email-configuration)
10. [OAuth Setup (Optional)](#oauth-setup-optional)
11. [Post-Deployment Testing](#post-deployment-testing)
12. [Troubleshooting](#troubleshooting)

---

## Project Overview

HiFi Delivery Eats is a Flask-based food delivery web application featuring:
- User authentication (email + social login)
- Menu management
- Order processing
- Delivery agent management
- Admin dashboard with analytics
- Email notifications

**Technology Stack:**
- Backend: Python 3.10+ with Flask
- Database: SQLite (for development) / PostgreSQL (recommended for production)
- Frontend: HTML, CSS, JavaScript with Jinja2 templates
- Server: Gunicorn (production WSGI server)

---

## Prerequisites

Before deploying, ensure you have:

1. **A GitHub account** with the repository forked/cloned
2. **A Gmail account** for SMTP email functionality (with App Password enabled)
3. **An account on your chosen hosting platform** (Render, Heroku, or Railway)
4. **(Optional) Google Cloud Console account** for Google OAuth
5. **(Optional) Facebook/Twitter developer accounts** for social login

---

## Deployment Options

| Platform | Free Tier | Ease of Use | Recommended For |
|----------|-----------|-------------|-----------------|
| **Render.com** | ✅ Yes | ⭐⭐⭐⭐⭐ | Beginners |
| **Heroku** | ❌ Paid only | ⭐⭐⭐⭐ | Professional use |
| **Railway** | ✅ Limited | ⭐⭐⭐⭐ | Quick prototypes |

---

## Option A: Deploy on Render.com (Recommended)

Render.com offers a free tier perfect for this application.

### Step 1: Create a Render Account

1. Go to [render.com](https://render.com)
2. Click **"Get Started for Free"**
3. Sign up with GitHub (recommended) or email

### Step 2: Connect Your Repository

1. After logging in, click **"New +"** button
2. Select **"Web Service"**
3. Connect your GitHub account if not already connected
4. Find and select your `Hifi_Delivery_Eats` repository
5. Click **"Connect"**

### Step 3: Configure the Web Service

Fill in the following configuration:

| Field | Value |
|-------|-------|
| **Name** | `hifi-delivery-eats` |
| **Region** | Choose closest to your users |
| **Branch** | `deploy` (or your main branch) |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt && python download_nltk_resources.py` |
| **Start Command** | `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120` |
| **Instance Type** | `Free` |

### Step 4: Add Environment Variables

Click on **"Environment"** tab and add the following:

```
SECRET_KEY=<generate-a-32-character-random-string>
JWT_SECRET=<generate-another-random-string>
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-gmail-app-password
EMAIL_ADDRESS=your-email@gmail.com
EMAIL_PASSWORD=your-gmail-app-password
```

**To generate a secure SECRET_KEY:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Step 5: Add Persistent Disk (Important for SQLite)

1. Scroll down to **"Disks"** section
2. Click **"Add Disk"**
3. Set **Name**: `data`
4. Set **Mount Path**: `/data`
5. Set **Size**: `1 GB` (free tier allows 1 GB)

### Step 6: Deploy

1. Click **"Create Web Service"**
2. Wait for the build and deployment to complete (5-10 minutes)
3. Once deployed, you'll see a URL like `https://hifi-delivery-eats.onrender.com`

---

## Option B: Deploy on Heroku

### Step 1: Create a Heroku Account

1. Go to [heroku.com](https://heroku.com)
2. Create an account
3. Install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli)

### Step 2: Login and Create App

```bash
# Login to Heroku
heroku login

# Create a new app
heroku create hifi-delivery-eats

# Set the Python version
heroku config:set PYTHON_VERSION=3.10.12
```

### Step 3: Set Environment Variables

```bash
heroku config:set SECRET_KEY="your-secret-key"
heroku config:set JWT_SECRET="your-jwt-secret"
heroku config:set EMAIL_USER="your-email@gmail.com"
heroku config:set EMAIL_PASS="your-app-password"
heroku config:set EMAIL_ADDRESS="your-email@gmail.com"
heroku config:set EMAIL_PASSWORD="your-app-password"
```

### Step 4: Deploy

```bash
# Push to Heroku
git push heroku deploy:main

# Open the app
heroku open
```

---

## Option C: Deploy on Railway

### Step 1: Create a Railway Account

1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub

### Step 2: Deploy from GitHub

1. Click **"New Project"**
2. Select **"Deploy from GitHub repo"**
3. Select your repository
4. Railway will auto-detect Flask

### Step 3: Configure Environment Variables

In the Railway dashboard:
1. Go to **Variables** tab
2. Add all required environment variables (same as Render)

### Step 4: Generate Domain

1. Go to **Settings** tab
2. Click **"Generate Domain"**
3. Your app will be available at the generated URL

---

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key for sessions | `a7b8c9d0e1f2...` (32+ chars) |
| `JWT_SECRET` | JWT token signing key | `x1y2z3a4b5...` (32+ chars) |
| `EMAIL_USER` | Gmail address for SMTP | `yourapp@gmail.com` |
| `EMAIL_PASS` | Gmail App Password | `abcd efgh ijkl mnop` |
| `EMAIL_ADDRESS` | Same as EMAIL_USER | `yourapp@gmail.com` |
| `EMAIL_PASSWORD` | Same as EMAIL_PASS | `abcd efgh ijkl mnop` |

### Optional Variables (for OAuth)

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `FACEBOOK_CLIENT_ID` | Facebook OAuth client ID |
| `FACEBOOK_CLIENT_SECRET` | Facebook OAuth client secret |
| `TWITTER_CLIENT_ID` | Twitter OAuth client ID |
| `TWITTER_CLIENT_SECRET` | Twitter OAuth client secret |

---

## Database Setup

The application uses SQLite by default with a pre-configured database (`existing_database.db`).

### For Production (Recommended: PostgreSQL)

For better performance and reliability in production, consider migrating to PostgreSQL:

1. Create a PostgreSQL database on your hosting provider
2. Update the database connection in `app.py` to use PostgreSQL
3. Install `psycopg2-binary` package

**Note:** The current setup includes a SQLite database that will work for small to medium traffic.

---

## Email Configuration

The application uses Gmail SMTP for sending emails. Follow these steps:

### Step 1: Enable 2-Factor Authentication

1. Go to [Google Account Settings](https://myaccount.google.com/)
2. Navigate to **Security**
3. Enable **2-Step Verification**

### Step 2: Generate App Password

1. After enabling 2FA, go back to **Security**
2. Click on **App passwords** (under "2-Step Verification")
3. Select **Mail** and **Other (Custom name)**
4. Name it "HiFi Delivery Eats"
5. Click **Generate**
6. Copy the 16-character password (format: `xxxx xxxx xxxx xxxx`)

### Step 3: Use in Environment Variables

```
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=xxxx xxxx xxxx xxxx
EMAIL_ADDRESS=your-email@gmail.com
EMAIL_PASSWORD=xxxx xxxx xxxx xxxx
```

---

## OAuth Setup (Optional)

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the **Google+ API** or **Google Identity API**
4. Go to **Credentials** > **Create Credentials** > **OAuth 2.0 Client IDs**
5. Set the authorized redirect URI to:
   - `https://your-app-url.com/google/callback`
6. Copy the Client ID and Client Secret

### Facebook OAuth

1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create a new app
3. Add **Facebook Login** product
4. Set the redirect URI to:
   - `https://your-app-url.com/facebook/callback`
5. Copy the App ID and App Secret

---

## Post-Deployment Testing

After deployment, verify the following:

### 1. Homepage Loads
- Visit your deployment URL
- The homepage should display correctly

### 2. User Registration
- Click "Sign Up"
- Create a test account
- Check if confirmation email is received

### 3. User Login
- Login with the test account
- Verify you can access the menu

### 4. Admin Functions (if applicable)
- Login with admin credentials
- Test admin dashboard features

### 5. Order Flow
- Add items to cart
- Proceed to checkout
- Verify order confirmation

---

## Troubleshooting

### Build Fails

**Problem:** Dependencies fail to install

**Solution:**
```bash
# Check Python version
python --version

# Ensure requirements.txt is up to date
pip install -r requirements.txt
```

### App Crashes on Start

**Problem:** Application doesn't start

**Solution:**
1. Check logs in your hosting dashboard
2. Verify all environment variables are set
3. Ensure database file exists

### Emails Not Sending

**Problem:** Email functionality not working

**Solution:**
1. Verify Gmail App Password is correct
2. Check if "Less secure app access" is needed (deprecated)
3. Ensure EMAIL_USER and EMAIL_PASS are set correctly

### Database Errors

**Problem:** SQLite database not found

**Solution:**
1. Ensure `existing_database.db` is in the repository
2. For Render: Add a persistent disk
3. Check file permissions

### OAuth Redirect Errors

**Problem:** OAuth login fails

**Solution:**
1. Update redirect URIs in OAuth provider settings
2. Use HTTPS URLs in production
3. Verify client ID and secret are correct

---

## Support

If you encounter issues:

1. Check the application logs in your hosting dashboard
2. Review the error messages carefully
3. Ensure all environment variables are correctly set
4. Verify the database file is accessible

---

## Quick Reference

### Deploy Checklist

- [ ] Repository pushed to GitHub
- [ ] Account created on hosting platform
- [ ] Web service created
- [ ] Environment variables configured
- [ ] Build command set correctly
- [ ] Start command set correctly
- [ ] (If using SQLite) Persistent disk added
- [ ] Deployment successful
- [ ] Application accessible via URL
- [ ] Email sending works
- [ ] User registration works
- [ ] Login works
- [ ] Order flow works

### Important Files

| File | Purpose |
|------|---------|
| `app.py` | Main Flask application |
| `requirements.txt` | Python dependencies |
| `Procfile` | Process configuration (Heroku) |
| `render.yaml` | Render.com configuration |
| `runtime.txt` | Python version specification |
| `.env.example` | Environment variables template |
| `existing_database.db` | SQLite database |

---

Happy Deploying! 🚀
