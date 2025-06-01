import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import pickle
import numpy as np
import pandas as pd
import re
import ssl
import socket
from datetime import datetime
from feature import FeatureExtraction
import warnings
import urllib3

# Suppress all warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class URLAnalyzer:
    def __init__(self):
        # Load the phishing detection model
        with open("pickle/model.pkl", "rb") as file:
            self.model = pickle.load(file)
        
        # Known legitimate domains
        self.legitimate_domains = {
            'bsnl': ['bsnl.co.in', 'bsnl.in', 'bsnltower.com'],
            'google': ['google.com', 'google.co.in', 'google.org', 'google.net'],
            'facebook': ['facebook.com', 'fb.com', 'facebook.net'],
            'amazon': ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de'],
            'microsoft': ['microsoft.com', 'msn.com', 'live.com', 'outlook.com'],
            'apple': ['apple.com', 'icloud.com', 'apple.co.uk'],
            'netflix': ['netflix.com', 'netflix.net'],
            'paypal': ['paypal.com', 'paypal.me'],
            'twitter': ['twitter.com', 't.co'],
            'instagram': ['instagram.com', 'instagr.am'],
            'linkedin': ['linkedin.com', 'linked.in'],
            'whatsapp': ['whatsapp.com', 'wa.me'],
            'youtube': ['youtube.com', 'youtu.be'],
            'github': ['github.com', 'github.io'],
            'dropbox': ['dropbox.com', 'db.tt'],
            'spotify': ['spotify.com', 'spoti.fi'],
            'reddit': ['reddit.com', 'redd.it'],
            'discord': ['discord.com', 'discord.gg'],
            'slack': ['slack.com', 'slack.works'],
            'zoom': ['zoom.us', 'zoom.com']
        }
    
    def check_brand_impersonation(self, url):
        """Check if the website is impersonating a known brand"""
        domain = urlparse(url).netloc.lower()
        warnings = []
        
        # Check for brand impersonation
        for brand, legitimate_domains in self.legitimate_domains.items():
            # Check if brand name appears in domain
            if brand in domain:
                # Check if it matches any legitimate domain
                if not any(legit in domain for legit in legitimate_domains):
                    warnings.append(f"⚠️ Warning: This domain contains '{brand.upper()}' but doesn't match any known legitimate {brand.upper()} domains")
        
        # Check for common brand name variations
        brand_variations = {
            'google': ['gooogle', 'gogle', 'googl'],
            'facebook': ['facebok', 'faceboook', 'fb'],
            'amazon': ['amzon', 'amazn', 'amzn'],
            'microsoft': ['microsft', 'msft', 'ms'],
            'apple': ['appel', 'appl', 'apl'],
            'paypal': ['paypal', 'paypall', 'paypl'],
            'netflix': ['netflx', 'netfliks', 'netflicks']
        }
        
        for brand, variations in brand_variations.items():
            if any(var in domain for var in variations):
                if not any(legit in domain for legit in self.legitimate_domains.get(brand, [])):
                    warnings.append(f"⚠️ Warning: This domain contains a variation of '{brand.upper()}' but doesn't match any known legitimate {brand.upper()} domains")
        
        return warnings

    def analyze_content(self, url):
        """Analyze website content for suspicious patterns"""
        try:
            # Create a session with proper SSL verification
            session = requests.Session()
            session.verify = True  # Enable SSL verification
            
            # Try with SSL verification first
            try:
                response = session.get(url, timeout=10)
            except requests.exceptions.SSLError:
                # If SSL verification fails, try without verification as fallback
                session.verify = False
                response = session.get(url, timeout=10)
                print("⚠️ Warning: SSL certificate verification failed, proceeding with unverified connection")
            
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=UserWarning)
                soup = BeautifulSoup(response.text, 'lxml')
            warnings = []
            
            # Check for suspicious keywords
            suspicious_keywords = [
                'urgent', 'immediate', 'verify', 'account', 'password', 'login',
                'update', 'security', 'suspicious', 'fraud', 'verify identity',
                'personal information', 'bank details', 'credit card'
            ]
            
            text = soup.get_text().lower()
            found_keywords = [word for word in suspicious_keywords if word in text]
            if found_keywords:
                warnings.append(f"⚠️ Warning: Found suspicious keywords: {', '.join(found_keywords)}")
            
            # Check for forms collecting sensitive information
            forms = soup.find_all('form')
            sensitive_fields = ['password', 'credit', 'card', 'ssn', 'social security']
            for form in forms:
                form_text = form.get_text().lower()
                if any(field in form_text for field in sensitive_fields):
                    warnings.append("⚠️ Warning: Form found collecting sensitive information")
            
            return warnings
        except Exception as e:
            return [f"⚠️ Warning: Could not analyze content: {str(e)}"]

    def check_ssl_certificate(self, url):
        """Check SSL certificate details"""
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme == 'https':
                return ["⚠️ Warning: URL is not using HTTPS"]
                
            hostname = parsed_url.netloc
            context = ssl.create_default_context()
            
            # Set timeout for the connection
            sock = socket.create_connection((hostname, 443), timeout=5)
            sock.settimeout(5)  # Set socket timeout
            
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
            warnings = []
            
            # Check certificate expiration
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            if days_until_expiry < 30:
                warnings.append(f"⚠️ Warning: SSL certificate expires in {days_until_expiry} days")
            
            # Check if certificate is self-signed
            if cert['issuer'] == cert['subject']:
                warnings.append("⚠️ Warning: Self-signed SSL certificate detected")
            
            # Check certificate chain
            if not cert.get('issuer'):
                warnings.append("⚠️ Warning: Certificate issuer information missing")
            
            # Check certificate subject
            if not cert.get('subject'):
                warnings.append("⚠️ Warning: Certificate subject information missing")
            
            # Check if hostname matches certificate
            cert_hostname = cert.get('subjectAltName', [])
            hostname = parsed_url.netloc.lower()
            
            # Function to check if a hostname matches a certificate name
            def matches_cert_name(cert_name, hostname):
                if cert_name.startswith('*.'):
                    # Handle wildcard certificates
                    base_domain = cert_name[2:]  # Remove the '*.'
                    return hostname.endswith(base_domain)
                return cert_name.lower() == hostname
            
            # Check all certificate names
            if not any(matches_cert_name(str(name[1]), hostname) for name in cert_hostname):
                warnings.append("⚠️ Warning: Certificate hostname mismatch")
            
            return warnings
            
        except socket.timeout:
            return ["⚠️ Warning: SSL certificate check timed out"]
        except ssl.SSLError as e:
            return [f"⚠️ Warning: SSL error: {str(e)}"]
        except Exception as e:
            return [f"⚠️ Warning: Could not verify SSL certificate: {str(e)}"]

    def get_prediction(self, url):
        """Get phishing prediction for a URL"""
        obj = FeatureExtraction(url)
        features = obj.getFeaturesList()
        
        # Create feature names that match the model's training data
        feature_names = [
            'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
            'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
            'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
            'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
        ]
        
        # Convert to DataFrame with feature names
        x = pd.DataFrame([features], columns=feature_names)
        
        y_pred = self.model.predict(x)[0]
        y_pro_phishing = self.model.predict_proba(x)[0,0]
        y_pro_non_phishing = self.model.predict_proba(x)[0,1]
        return {
            "is_phishing": bool(y_pred),
            "phishing_prob": float(y_pro_phishing),
            "safe_prob": float(y_pro_non_phishing)
        }

    def extract_links_bs4(self, url):
        """Extract static links using BeautifulSoup"""
        try:
            # Create a session with proper SSL verification
            session = requests.Session()
            session.verify = True  # Enable SSL verification
            
            # Suppress SSL verification warnings
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Try with SSL verification first
            try:
                response = session.get(url, timeout=5)
            except requests.exceptions.SSLError:
                # If SSL verification fails, try without verification as fallback
                session.verify = False
                response = session.get(url, timeout=5)
                print("⚠️ Warning: SSL certificate verification failed, proceeding with unverified connection")
            
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=UserWarning)
                soup = BeautifulSoup(response.text, 'lxml')
            links = set()
            for tag in soup.find_all(['a', 'link', 'script', 'iframe']):
                attr = tag.get('href') or tag.get('src')
                if attr:
                    full_url = urljoin(url, attr)
                    links.add(full_url)
            return links
        except Exception as e:
            print(f"Error extracting static links: {e}")
            return set()

    def extract_links_selenium(self, url):
        """Extract dynamic links using Selenium"""
        try:
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-infobars')
            options.add_argument('--disable-notifications')
            options.add_argument('--disable-popup-blocking')
            options.add_argument('--disable-web-security')
            options.add_argument('--disable-features=IsolateOrigins,site-per-process')
            options.add_argument('--disable-site-isolation-trials')
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(10)  # Reduced timeout to 10 seconds
            
            try:
                print("Loading page...")
                driver.get(url)
                time.sleep(1)  # Reduced wait time to 1 second

                print("Extracting links...")
                links = set()
                # Use JavaScript to get all links at once instead of XPath
                hrefs = driver.execute_script("""
                    return Array.from(document.querySelectorAll('a[href], link[href], script[src], iframe[src]'))
                        .map(el => el.href || el.src)
                        .filter(href => href && href.startsWith('http'));
                """)
                links.update(hrefs)

                # Check for popup alerts
                popup = False
                try:
                    driver.switch_to.alert
                    popup = True
                except:
                    pass

                redirects = driver.execute_script("return window.performance.getEntriesByType('navigation')")
                return links, popup, redirects
            except Exception as e:
                print(f"Warning: Selenium encountered an error: {str(e)}")
                return set(), False, []
            finally:
                driver.quit()
        except Exception as e:
            print(f"Error initializing Selenium: {str(e)}")
            return set(), False, []

    def analyze_website(self, url):
        """Analyze a website and all its URLs for phishing"""
        print(f"\n🔎 Analyzing website: {url}")
        
        try:
            # Get main URL analysis
            print("1/5: Analyzing main URL...")
            main_analysis = self.get_prediction(url)
            
            # Extract all links with timeout
            print("2/5: Extracting links (this may take a few seconds)...")
            static_links = self.extract_links_bs4(url)
            print(f"Found {len(static_links)} static links")
            
            print("3/5: Extracting dynamic links...")
            dynamic_links, popup_found, redirects = self.extract_links_selenium(url)
            print(f"Found {len(dynamic_links)} dynamic links")
            
            # Limit the number of links to analyze
            MAX_LINKS_TO_ANALYZE = 10
            all_links = list(static_links.union(dynamic_links))[:MAX_LINKS_TO_ANALYZE]
            print(f"Analyzing top {len(all_links)} links...")
            
            # Analyze each link with timeout
            print("4/5: Analyzing links...")
            link_analyses = {}
            for i, link in enumerate(all_links, 1):
                try:
                    print(f"Analyzing link {i}/{len(all_links)}: {link}")
                    link_analyses[link] = self.get_prediction(link)
                except Exception as e:
                    print(f"Error analyzing link {link}: {e}")
            
            # Additional security checks
            print("5/5: Performing security checks...")
            print("- Checking for brand impersonation...")
            brand_warnings = self.check_brand_impersonation(url)
            
            print("- Analyzing content...")
            content_warnings = self.analyze_content(url)
            
            print("- Checking SSL certificate...")
            ssl_warnings = self.check_ssl_certificate(url)
            
            # Prepare results
            results = {
                "main_url": {
                    "url": url,
                    "analysis": main_analysis
                },
                "total_links": len(all_links),
                "links_analysis": link_analyses,
                "popup_detected": popup_found,
                "redirect_count": len(redirects),
                "security_warnings": {
                    "brand_impersonation": brand_warnings,
                    "content_analysis": content_warnings,
                    "ssl_analysis": ssl_warnings
                }
            }
            
            print("\n✅ Analysis complete!")
            return results
        except Exception as e:
            print(f"❌ Error during website analysis: {str(e)}")
            return None

    def explain_features(self, features, feature_names):
        """Explain the analysis of each feature"""
        explanations = []
        
        feature_explanations = {
            'UsingIP': {
                1: "URL is not an IP address (safe)",
                -1: "URL is an IP address (suspicious)"
            },
            'LongURL': {
                1: "URL length is appropriate (safe)",
                0: "URL length is medium (neutral)",
                -1: "URL is very long (suspicious)"
            },
            'ShortURL': {
                1: "Not a shortened URL (safe)",
                -1: "Uses URL shortening service (suspicious)"
            },
            'Symbol@': {
                1: "No @ symbol in URL (safe)",
                -1: "Contains @ symbol (suspicious)"
            },
            'Redirecting//': {
                1: "No suspicious redirects (safe)",
                -1: "Multiple redirects detected (suspicious)"
            },
            'PrefixSuffix-': {
                1: "No hyphens in domain (safe)",
                -1: "Contains hyphens in domain (suspicious)"
            },
            'SubDomains': {
                1: "Appropriate number of subdomains (safe)",
                0: "Medium number of subdomains (neutral)",
                -1: "Too many subdomains (suspicious)"
            },
            'HTTPS': {
                1: "Uses HTTPS (safe)",
                -1: "Does not use HTTPS (suspicious)"
            },
            'DomainRegLen': {
                1: "Long domain registration (safe)",
                -1: "Short domain registration (suspicious)"
            },
            'Favicon': {
                1: "Proper favicon source (safe)",
                -1: "Suspicious favicon source (suspicious)"
            },
            'NonStdPort': {
                1: "Uses standard port (safe)",
                -1: "Uses non-standard port (suspicious)"
            },
            'HTTPSDomainURL': {
                1: "No HTTPS in domain (safe)",
                -1: "HTTPS in domain (suspicious)"
            },
            'RequestURL': {
                1: "Proper resource requests (safe)",
                0: "Medium resource requests (neutral)",
                -1: "Suspicious resource requests (suspicious)"
            },
            'AnchorURL': {
                1: "Proper anchor tags (safe)",
                0: "Medium anchor tag quality (neutral)",
                -1: "Suspicious anchor tags (suspicious)"
            },
            'LinksInScriptTags': {
                1: "Proper script links (safe)",
                0: "Medium script link quality (neutral)",
                -1: "Suspicious script links (suspicious)"
            },
            'ServerFormHandler': {
                1: "Proper form handling (safe)",
                0: "Medium form handling quality (neutral)",
                -1: "Suspicious form handling (suspicious)"
            },
            'InfoEmail': {
                1: "No suspicious email collection (safe)",
                -1: "Suspicious email collection detected (suspicious)"
            },
            'AbnormalURL': {
                1: "Normal URL structure (safe)",
                -1: "Abnormal URL structure (suspicious)"
            },
            'WebsiteForwarding': {
                1: "No suspicious forwarding (safe)",
                0: "Medium forwarding (neutral)",
                -1: "Suspicious forwarding detected (suspicious)"
            },
            'StatusBarCust': {
                1: "No suspicious status bar customization (safe)",
                -1: "Suspicious status bar customization (suspicious)"
            },
            'DisableRightClick': {
                1: "No right-click disabling (safe)",
                -1: "Right-click disabled (suspicious)"
            },
            'UsingPopupWindow': {
                1: "No suspicious popups (safe)",
                -1: "Suspicious popups detected (suspicious)"
            },
            'IframeRedirection': {
                1: "No suspicious iframes (safe)",
                -1: "Suspicious iframes detected (suspicious)"
            },
            'AgeofDomain': {
                1: "Domain is old enough (safe)",
                0: "Domain is medium age (neutral)",
                -1: "Domain is too new (suspicious)"
            },
            'DNSRecording': {
                1: "Proper DNS records (safe)",
                -1: "Suspicious DNS records (suspicious)"
            },
            'WebsiteTraffic': {
                1: "Good traffic (safe)",
                0: "Medium traffic (neutral)",
                -1: "Low traffic (suspicious)"
            },
            'PageRank': {
                1: "Good PageRank (safe)",
                -1: "Low PageRank (suspicious)"
            },
            'GoogleIndex': {
                1: "Properly indexed (safe)",
                -1: "Not properly indexed (suspicious)"
            },
            'LinksPointingToPage': {
                1: "Good number of incoming links (safe)",
                0: "Medium number of incoming links (neutral)",
                -1: "Too many incoming links (suspicious)"
            },
            'StatsReport': {
                1: "No suspicious statistics (safe)",
                -1: "Suspicious statistics detected (suspicious)"
            }
        }
        
        for feature, value in zip(feature_names, features):
            if feature in feature_explanations and value in feature_explanations[feature]:
                explanations.append(f"{feature}: {feature_explanations[feature][value]}")
        
        return explanations

    def print_results(self, results):
        """Print analysis results in a readable format"""
        print("\n=== Main URL Analysis ===")
        main = results["main_url"]
        print(f"URL: {main['url']}")
        print(f"Safety Score: {main['analysis']['safe_prob']*100:.2f}%")
        print(f"Risk Score: {main['analysis']['phishing_prob']*100:.2f}%")
        
        # Get feature explanations
        obj = FeatureExtraction(main['url'])
        features = obj.getFeaturesList()
        #print("\nDebug - Features extracted:")
        #print(features)  # Debug print
        
        feature_names = [
            'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
            'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
            'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
            'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
        ]
        
        #print("\n=== Feature Analysis ===")
        #explanations = self.explain_features(features, feature_names)
        #print("\nDebug - Feature explanations:")
        #print(explanations)  # Debug print
        #for explanation in explanations:
        #    print(f"  {explanation}")
        
        print(f"\n=== SSL Certificate Analysis ===")
        ssl_warnings = results["security_warnings"]["ssl_analysis"]
        if ssl_warnings:
            for warning in ssl_warnings:
                print(f"  {warning}")
        else:
            print("  ✅ SSL certificate is valid and secure")
        
        print(f"\n=== Links Analysis ({results['total_links']} links found) ===")
        for url, analysis in results["links_analysis"].items():
            print(f"\nURL: {url}")
            print(f"Safety Score: {analysis['safe_prob']*100:.2f}%")
            print(f"Risk Score: {analysis['phishing_prob']*100:.2f}%")
        
        print(f"\n⚠️ Popup Detected: {'Yes' if results['popup_detected'] else 'No'}")
        print(f"🔁 Number of Redirects: {results['redirect_count']}")
        
        # Print security warnings
        print("\n=== Security Warnings ===")
        for category, warnings in results["security_warnings"].items():
            if category != "ssl_analysis" and warnings:  # Skip SSL warnings as they're already printed
                print(f"\n{category.replace('_', ' ').title()}:")
                for warning in warnings:
                    print(f"  {warning}")

if __name__ == "__main__":
    analyzer = URLAnalyzer()
    test_url = "https://www.bsnl.co.in/"
    #test_url = "https://bsnlmobiletower.in/"
    results = analyzer.analyze_website(test_url)
    analyzer.print_results(results) 