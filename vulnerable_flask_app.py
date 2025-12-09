#!/usr/bin/env python3
"""
Vulnerable Flask E-Commerce Application
========================================

This is an INTENTIONALLY VULNERABLE application for demonstrating
HTTP Parameter Pollution (HPP) attacks.

VULNERABILITY: Price Manipulation via HPP
- Flask uses FIRST parameter value by default (request.args.get())
- This app simulates a backend bug where payment processing uses first value
- Attacker can manipulate the price by sending: ?price=1&price=999

DO NOT USE IN PRODUCTION!
This app is for educational/testing purposes only.
"""

from flask import Flask, request, jsonify, render_template_string
import logging

app = Flask(__name__)

# Disable Flask debug mode for cleaner output
app.config['DEBUG'] = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>VulnShop - E-Commerce Demo</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            color: white;
            padding: 40px 20px;
        }
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
        }
        .warning-banner {
            background: #ff6b6b;
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: center;
            font-weight: bold;
        }
        .products {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin-top: 40px;
        }
        .product-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            transition: transform 0.3s;
        }
        .product-card:hover {
            transform: translateY(-10px);
        }
        .product-image {
            font-size: 80px;
            text-align: center;
            margin-bottom: 20px;
        }
        .product-name {
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }
        .product-price {
            font-size: 32px;
            color: #667eea;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .buy-button {
            display: block;
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            text-align: center;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            transition: opacity 0.3s;
        }
        .buy-button:hover {
            opacity: 0.9;
        }
        .framework-info {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-top: 40px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛒 VulnShop</h1>
            <p>Intentionally Vulnerable E-Commerce Demo</p>
        </div>

        <div class="warning-banner">
            ⚠️ WARNING: This application is INTENTIONALLY VULNERABLE for educational purposes!<br>
            It demonstrates HTTP Parameter Pollution (HPP) attacks.
        </div>

        <div class="products">
            <div class="product-card">
                <div class="product-image">💻</div>
                <div class="product-name">Premium Laptop</div>
                <div class="product-price">$999</div>
                <a href="/checkout?item=laptop&price=999&quantity=1" class="buy-button">Buy Now</a>
            </div>

            <div class="product-card">
                <div class="product-image">🖱️</div>
                <div class="product-name">Wireless Mouse</div>
                <div class="product-price">$25</div>
                <a href="/checkout?item=mouse&price=25&quantity=1" class="buy-button">Buy Now</a>
            </div>

            <div class="product-card">
                <div class="product-image">⌨️</div>
                <div class="product-name">Mechanical Keyboard</div>
                <div class="product-price">$75</div>
                <a href="/checkout?item=keyboard&price=75&quantity=1" class="buy-button">Buy Now</a>
            </div>
        </div>

        <div class="framework-info">
            <strong>Framework:</strong> Flask (Python)<br>
            <strong>Vulnerability:</strong> HTTP Parameter Pollution (HPP)<br>
            <strong>Attack:</strong> Try modifying the URL to add duplicate price parameters!
        </div>
    </div>
</body>
</html>
'''

CHECKOUT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Checkout - VulnShop</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            color: white;
            padding: 40px 20px 20px 20px;
        }
        .checkout-card {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-top: 20px;
        }
        .order-title {
            font-size: 28px;
            color: #333;
            margin-bottom: 30px;
            text-align: center;
        }
        .order-item {
            display: flex;
            justify-content: space-between;
            padding: 15px 0;
            border-bottom: 1px solid #eee;
            font-size: 18px;
        }
        .order-item:last-child {
            border-bottom: none;
        }
        .order-item-label {
            color: #666;
        }
        .order-item-value {
            font-weight: bold;
            color: #333;
        }
        .total-section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 30px 0;
        }
        .total-row {
            display: flex;
            justify-content: space-between;
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }
        .charged-row {
            display: flex;
            justify-content: space-between;
            font-size: 28px;
            font-weight: bold;
            color: #667eea;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 2px solid #667eea;
        }
        .vulnerability-warning {
            background: #ff6b6b;
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: center;
        }
        .vulnerability-warning h3 {
            margin-bottom: 10px;
            font-size: 24px;
        }
        .vulnerability-details {
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .vulnerability-details h4 {
            color: #856404;
            margin-bottom: 10px;
        }
        .vulnerability-details code {
            background: #fff;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .button-group {
            display: flex;
            gap: 15px;
            margin-top: 30px;
        }
        .button {
            flex: 1;
            padding: 15px;
            text-align: center;
            text-decoration: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            transition: opacity 0.3s;
        }
        .button:hover {
            opacity: 0.9;
        }
        .button-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .button-secondary {
            background: #6c757d;
            color: white;
        }
        .success-icon {
            font-size: 60px;
            text-align: center;
            margin-bottom: 20px;
        }
        .url-display {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            word-break: break-all;
            color: #495057;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛒 Checkout</h1>
        </div>

        <div class="checkout-card">
            <div class="success-icon">✅</div>
            <h2 class="order-title">Order Confirmation</h2>

            <div class="order-item">
                <span class="order-item-label">Item:</span>
                <span class="order-item-value">{{ item }}</span>
            </div>

            <div class="order-item">
                <span class="order-item-label">Quantity:</span>
                <span class="order-item-value">{{ quantity }}</span>
            </div>

            <div class="order-item">
                <span class="order-item-label">Unit Price:</span>
                <span class="order-item-value">${{ price_display }}</span>
            </div>

            <div class="total-section">
                <div class="total-row">
                    <span>Total Display:</span>
                    <span>${{ total_display }}</span>
                </div>
                <div class="charged-row">
                    <span>Amount Charged:</span>
                    <span>${{ total_charged }}</span>
                </div>
            </div>

            {% if is_vulnerable %}
            <div class="vulnerability-warning">
                <h3>⚠️ HPP VULNERABILITY DETECTED!</h3>
                <p>Price manipulation successful!</p>
            </div>

            <div class="vulnerability-details">
                <h4>🔍 Attack Details:</h4>
                <p><strong>Display Price:</strong> ${{ price_display }} (what the user sees)</p>
                <p><strong>Charged Price:</strong> ${{ price_charged }} (what Flask processes)</p>
                <p><strong>Financial Impact:</strong> ${{ price_display - price_charged }} loss per transaction!</p>
                <br>
                <p><strong>Parameters Received:</strong></p>
                <ul>
                    {% for p in prices_received %}
                    <li><code>price={{ p }}</code></li>
                    {% endfor %}
                </ul>
                <br>
                <p><strong>Why this works:</strong> Flask's <code>request.args.get('price')</code> returns the FIRST value ({{ price_charged }}), but the display logic shows the LAST value ({{ price_display }}).</p>
            </div>
            {% endif %}

            <div class="url-display">
                <strong>Request URL:</strong><br>
                {{ request_url }}
            </div>

            <div class="button-group">
                <a href="/" class="button button-secondary">← Back to Shop</a>
                <a href="#" class="button button-primary" onclick="alert('Payment processed!'); return false;">Complete Purchase</a>
            </div>
        </div>
    </div>
</body>
</html>
'''


@app.route('/')
def home():
    """Home page with product catalog."""
    return render_template_string(HOME_TEMPLATE)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    """
    Vulnerable checkout endpoint with HTML frontend.

    VULNERABILITY: HPP Price Manipulation

    Normal request:
        GET /checkout?item=laptop&price=999
        Response: Shows $999 charged

    Attack request:
        GET /checkout?item=laptop&price=1&price=999
        Response: Shows $1 charged, $999 displayed!
    """

    # Get parameters
    item = request.args.get('item', 'unknown')
    quantity = request.args.get('quantity', '1')

    # VULNERABLE CODE: Uses Flask's default behavior (FIRST value)
    price_for_charge = request.args.get('price', '0')

    # Get ALL price values
    all_prices = request.args.getlist('price')

    # Display price (shows LAST value when multiple exist)
    if len(all_prices) > 1:
        display_price = all_prices[-1]
    else:
        display_price = price_for_charge

    # Convert to integers
    try:
        charged_amount = int(price_for_charge)
        display_amount = int(display_price)
        qty = int(quantity)
    except ValueError:
        return jsonify({
            'error': 'Invalid price or quantity',
            'item': item
        }), 400

    # Calculate totals
    total_display = display_amount * qty
    total_charged = charged_amount * qty

    # Check if vulnerable
    is_vulnerable = (charged_amount != display_amount)

    if is_vulnerable:
        logger.warning(f"[HPP DETECTED] Price manipulation: Display=${display_amount}, Charged=${charged_amount}")
        logger.warning(f"[HPP DETECTED] All prices received: {all_prices}")

    # Render HTML template
    return render_template_string(
        CHECKOUT_TEMPLATE,
        item=item.capitalize(),
        quantity=qty,
        price_display=display_amount,
        price_charged=charged_amount,
        total_display=total_display,
        total_charged=total_charged,
        is_vulnerable=is_vulnerable,
        prices_received=all_prices,
        request_url=request.url
    )


@app.route('/products')
def products():
    """Sample products endpoint (JSON API)."""
    return jsonify({
        'products': [
            {'id': 1, 'name': 'Laptop', 'price': 999},
            {'id': 2, 'name': 'Mouse', 'price': 25},
            {'id': 3, 'name': 'Keyboard', 'price': 75}
        ]
    })


@app.errorhandler(404)
def not_found(error):
    """Custom 404 handler."""
    return jsonify({
        'error': '404 Not Found',
        'framework': 'Flask',
        'werkzeug': True
    }), 404


if __name__ == '__main__':
    print("=" * 70)
    print("  VULNERABLE FLASK E-COMMERCE APP")
    print("=" * 70)
    print()
    print("⚠️  WARNING: This app is INTENTIONALLY VULNERABLE for testing!")
    print()
    print("Endpoints:")
    print("  GET  /              - Home page with product catalog")
    print("  GET  /checkout      - Vulnerable checkout (HPP)")
    print("  GET  /products      - Product list (JSON)")
    print()
    print("Demo Instructions:")
    print("  1. Open http://127.0.0.1:5000 in your browser")
    print("  2. Click 'Buy Now' on the $999 laptop")
    print("  3. Note the URL and price")
    print("  4. Edit URL to: ...checkout?item=laptop&price=1&price=999")
    print("  5. See the HPP attack succeed!")
    print()
    print("Starting server on http://127.0.0.1:5000")
    print("=" * 70)
    print()

    # Run Flask app
    app.run(host='127.0.0.1', port=5000, debug=False)
