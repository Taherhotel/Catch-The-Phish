from flask import Flask, request, jsonify, render_template, send_file
import re
import io
from fpdf import FPDF
from features_extract import (
    extract_url_features,
    extract_keyword_features,
    extract_content_features,
    extract_domain_features,
    extract_redirection_count,
    get_certificate_info,
    get_domain_age,
    get_dns_record_count,
    check_spf_dmarc,
    is_shortened_url,
    analyze_url,
    calculate_risk_score,
    check_url_virustotal,
    check_google_safe_browsing
)
from datetime import datetime, timedelta
from flask_socketio import SocketIO
import os
import json
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import threading
import queue
import time

app = Flask(__name__, static_folder='static', template_folder='templates')
socketio = SocketIO(app, cors_allowed_origins="*")

# Mock database for testing
mock_db = []

# Queue for storing crawling results
crawl_results = queue.Queue()

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Feature Extraction API
@app.route('/index', methods=['POST'])
def index():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is missing."}), 400

        # Extract features
        features = {
            "url_features": extract_url_features(url),
            "keyword_features": extract_keyword_features(url),
            "content_features": extract_content_features(url),
            "domain_features": extract_domain_features(url),
            "redirection_count": extract_redirection_count(url),
            "certificate_info": get_certificate_info(url),
            "domain_age": get_domain_age(url),
            "dns_record_count": get_dns_record_count(url),
            "check_spf_dmarc": check_spf_dmarc(url),
            "is_shortened_url": is_shortened_url(url),
            'virus_total': check_url_virustotal(url),
            'google_safe_browsing': check_google_safe_browsing(url)
        }

        # Calculate risk score
        risk_score = calculate_risk_score(analyze_url(url))

        # Store in mock database
        mock_db.append({
            "url": url,
            "title": url,  # Using URL as title for mock
            "is_phishing": risk_score >= 40
        })

        return jsonify({
            "url": url,
            "features": features,
            'risk_score': risk_score,
            'verdict': (
                "Highly suspicious ⚠" if risk_score >= 70 else
                "Moderately suspicious ⚠" if risk_score >= 40 else
                "Likely safe ✅ (Still verify manually)"
            )
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get Crawled Data API
@app.route('/get_data', methods=['GET'])
def get_data():
    try:
        # Return last 50 entries from mock database
        return jsonify({
            "message": "Cleaned crawled data retrieved successfully",
            "data": mock_db[-50:] if mock_db else []
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Generate and Download PDF Report API
@app.route('/download_report', methods=['POST'])
def download_report():
    try:
        data = request.get_json()
        url = data.get("url")
        if not url:
            return jsonify({"error": "URL is missing"}), 400

        # Extract features and calculate risk score
        features = analyze_url(url)
        risk_score = calculate_risk_score(features)

        # Create PDF
        class PDF(FPDF):
            def header(self):
                # Set black background for the entire page
                self.set_fill_color(0, 0, 0)
                self.rect(0, 0, self.w, self.h, 'F')
                
                # Add logo
                try:
                    self.image('static/images/logo.png', 10, 8, 33)
                except:
                    pass  # Continue if logo not found
                
                # Add decorative line
                self.set_draw_color(255, 0, 0)
                self.set_line_width(0.5)
                self.line(10, 45, self.w - 10, 45)
                
                self.set_text_color(255, 255, 255)  # White color for header
                self.set_font('Arial', 'B', 24)
                self.cell(0, 20, 'Website Security Report', 0, 1, 'C')
                
                # Add timestamp
                self.set_font('Arial', 'I', 10)
                self.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
                self.ln(10)

            def footer(self):
                self.set_y(-15)
                # Add decorative line
                self.set_draw_color(255, 0, 0)
                self.set_line_width(0.5)
                self.line(10, self.h - 20, self.w - 10, self.h - 20)
                
                self.set_text_color(255, 255, 255)  # White color for footer
                self.set_font('Arial', 'I', 10)
                self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

            def create_table(self, headers, data, col_widths):
                # Table header
                self.set_fill_color(40, 40, 40)
                self.set_text_color(255, 255, 255)  # White color for headers
                self.set_font('Arial', 'B', 12)
                self.set_draw_color(255, 0, 0)  # Red border
                self.set_line_width(0.3)
                
                # Draw header cells with borders
                for i, header in enumerate(headers):
                    self.cell(col_widths[i], 10, header, 1, 0, 'C', True)
                self.ln()

                # Table data
                self.set_text_color(255, 0, 0)  # Red color for data
                self.set_font('Arial', '', 11)
                for row in data:
                    for i, value in enumerate(row):
                        self.cell(col_widths[i], 10, str(value), 1, 0, 'L')
                    self.ln()

            def section_title(self, title):
                self.ln(5)
                self.set_text_color(255, 255, 255)  # White color
                self.set_font('Arial', 'B', 14)
                self.cell(0, 10, title, 0, 1, 'L')
                # Add decorative line under section title
                self.set_draw_color(255, 0, 0)
                self.set_line_width(0.3)
                self.line(self.get_x(), self.get_y(), self.w - 10, self.get_y())
                self.ln(5)

        # Initialize PDF
        pdf = PDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_fill_color(0, 0, 0)  # Black background

        # URL Section
        pdf.section_title('Analyzed URL')
        pdf.set_text_color(255, 0, 0)  # Red color for URL
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, str(url), 0, 1)
        pdf.ln(5)

        # Risk Score Section
        pdf.section_title('Risk Analysis')

        # Risk Level Box
        pdf.set_draw_color(255, 0, 0)
        pdf.set_line_width(0.5)
        pdf.set_fill_color(20, 20, 20)
        pdf.rect(10, pdf.get_y(), pdf.w - 20, 30, 'FD')
        
        if risk_score >= 70:
            risk_color = (255, 0, 0)  # Red
            risk_text = "High Risk"
        elif risk_score >= 40:
            risk_color = (255, 165, 0)  # Orange
            risk_text = "Suspicious"
        else:
            risk_color = (0, 255, 0)  # Green
            risk_text = "Safe"

        pdf.set_text_color(*risk_color)
        pdf.set_font('Arial', 'B', 14)
        pdf.set_xy(15, pdf.get_y() + 5)
        pdf.cell(0, 10, f'Risk Score: {risk_score}%', 0, 1)
        pdf.set_xy(15, pdf.get_y())
        pdf.cell(0, 10, f'Risk Level: {risk_text}', 0, 1)
        pdf.ln(10)

        # URL Features Table
        pdf.section_title('URL Analysis')
        url_headers = ['Feature', 'Value']
        url_data = [
            ['URL Length', features['url']['length']],
            ['Number of Dots', features['url']['num_dots']],
            ['Number of Slashes', features['url']['num_slashes']],
            ['Number of Subdomains', features['url']['num_subdomains']],
            ['Contains IP', 'Yes' if features['url']['has_ip'] else 'No'],
            ['Uses HTTP', 'Yes' if features['url']['has_http'] else 'No'],
            ['Uses HTTPS', 'Yes' if features['url']['has_https'] else 'No'],
            ['Contains @ Symbol', 'Yes' if features['url']['has_at'] else 'No'],
            ['TLD', features['url']['tld']]
        ]
        pdf.create_table(url_headers, url_data, [80, 110])

        # Domain Information Table
        pdf.section_title('Domain Information')
        domain_headers = ['Feature', 'Value']
        domain_data = [
            ['Domain Length', features['domain']['domain_length']],
            ['Number of Subdomains', features['domain']['num_subdomains']],
            ['Contains Hyphen', 'Yes' if features['domain']['has_hyphen'] else 'No'],
            ['Suspicious TLD', 'Yes' if features['domain']['suspicious_tld'] else 'No']
        ]
        pdf.create_table(domain_headers, domain_data, [80, 110])

        # SSL Certificate Table
        pdf.section_title('SSL Certificate Information')
        ssl_headers = ['Feature', 'Value']
        ssl_data = [
            ['Certificate Issuer', features['certificate']['cert_issuer']],
            ['Certificate Validity (Days)', features['certificate']['cert_validity_days']],
            ['Days Until Expiry', features['certificate']['days_to_expiry']],
            ['Self-Signed', 'Yes' if features['certificate']['is_self_signed'] else 'No']
        ]
        pdf.create_table(ssl_headers, ssl_data, [80, 110])

        # Security Features Table
        pdf.section_title('Security Features')
        security_headers = ['Feature', 'Value']
        security_data = [
            ['SPF Present', 'Yes' if features['email']['spf_present'] else 'No'],
            ['DMARC Present', 'Yes' if features['email']['dmarc_present'] else 'No'],
            ['DNS Records Count', features['dns']['dns_record_count']],
            ['Domain Age (Days)', features['domain_age']['domain_age_days'] if features['domain_age']['domain_age_days'] != -1 else 'Unknown'],
            ['Is Shortened URL', 'Yes' if features['shortener']['is_shortened'] else 'No']
        ]
        pdf.create_table(security_headers, security_data, [80, 110])

        # VirusTotal Results Table
        pdf.section_title('VirusTotal Analysis')
        vt_headers = ['Category', 'Count']
        vt_data = [
            ['Malicious', features['virus_total'].get('malicious', 0)],
            ['Suspicious', features['virus_total'].get('suspicious', 0)],
            ['Harmless', features['virus_total'].get('harmless', 0)],
            ['Undetected', features['virus_total'].get('undetected', 0)],
            ['Timeout', features['virus_total'].get('timeout', 0)],
            ['Total Scans', features['virus_total'].get('total', 0)]
        ]
        pdf.create_table(vt_headers, vt_data, [80, 110])

        # Generate PDF
        try:
            pdf_output = pdf.output(dest='S').encode('latin-1', errors='ignore')
            buffer = io.BytesIO(pdf_output)
            buffer.seek(0)
            
            return send_file(
                buffer,
                mimetype='application/pdf',
                as_attachment=True,
                download_name='security_report.pdf'
            )
        except Exception as e:
            print(f"PDF Generation Error: {str(e)}")
            return jsonify({"error": "Failed to generate PDF report"}), 500

    except Exception as e:
        print(f"Report Generation Error: {str(e)}")
        return jsonify({"error": "Failed to process report request"}), 500

@app.route('/crawler')
def crawler():
    return render_template('crawler.html')

@app.route('/extract_features', methods=['POST'])
def extract_features():
    data = request.json
    url = data.get('url', '')
    title = data.get('title', '')
    content = data.get('content', '')
    is_phishing = data.get('is_phishing', '0')
    
    # Store the result in the queue
    crawl_results.put({
        'url': url,
        'title': title,
        'is_phishing': is_phishing,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    
    # Emit the result via WebSocket
    socketio.emit('crawl_result', {
        'url': url,
        'title': title,
        'is_phishing': is_phishing,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    
    return jsonify({'status': 'success'})

@app.route('/scan', methods=['POST'])
def scan():
    # ... existing scan code ...
    pass

@app.route('/dashboard')
def dashboard():
    # Get total counts
    total_sites = db.bank_websites.count_documents({})
    safe_sites = db.bank_websites.count_documents({"is_phishing": "0"})
    phishing_sites = db.bank_websites.count_documents({"is_phishing": "1"})
    phishing_rate = round((phishing_sites / total_sites * 100) if total_sites > 0 else 0, 2)

    # Get top phishing domains
    top_phishing_domains = list(db.bank_websites.find(
        {"is_phishing": "1"},
        {"url": 1, "crawled_at": 1, "confidence_score": 1, "_id": 0}
    ).sort("confidence_score", -1).limit(10))

    # Get recent activity
    recent_activity = list(db.bank_websites.find(
        {},
        {"url": 1, "crawled_at": 1, "is_phishing": 1, "title": 1, "_id": 0}
    ).sort("crawled_at", -1).limit(10))

    # Get daily trends for the last 7 days
    dates = []
    safe_trend = []
    phishing_trend = []
    
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        dates.append(date)
        
        start_of_day = datetime.strptime(date, '%Y-%m-%d')
        end_of_day = start_of_day + timedelta(days=1)
        
        safe_count = db.bank_websites.count_documents({
            "is_phishing": "0",
            "crawled_at": {"$gte": start_of_day, "$lt": end_of_day}
        })
        
        phishing_count = db.bank_websites.count_documents({
            "is_phishing": "1",
            "crawled_at": {"$gte": start_of_day, "$lt": end_of_day}
        })
        
        safe_trend.append(safe_count)
        phishing_trend.append(phishing_count)

    return render_template('dashboard.html',
                         total_sites=total_sites,
                         safe_sites=safe_sites,
                         phishing_sites=phishing_sites,
                         phishing_rate=phishing_rate,
                         top_phishing_domains=top_phishing_domains,
                         recent_activity=recent_activity,
                         dates=dates,
                         safe_trend=safe_trend,
                         phishing_trend=phishing_trend)

def background_processor():
    """Background task to process crawl results"""
    while True:
        try:
            result = crawl_results.get(timeout=1)
            # Process result if needed
            crawl_results.task_done()
        except queue.Empty:
            time.sleep(0.1)

if __name__ == '__main__':
    # Start background processor
    processor_thread = threading.Thread(target=background_processor, daemon=True)
    processor_thread.start()
    
    socketio.run(app, debug=True)
