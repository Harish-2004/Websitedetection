import requests, socket, ssl, json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from OpenSSL import crypto
import time
import warnings
import urllib3

# Suppress all warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_domain(url):
    return urlparse(url).netloc

def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        print("[-] IP Info Error:", e)
        return {}

def get_ssl_certificate_info(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        issuer = x509.get_issuer().CN
        expiry_date = x509.get_notAfter().decode('ascii')
        return {
            "issuer": issuer,
            "expiry": expiry_date
        }
    except Exception as e:
        print("[-] SSL Certificate Error:", e)
        return {}

def extract_links_bs4(url):
    try:
        # Create a session with proper SSL verification
        session = requests.Session()
        session.verify = True  # Enable SSL verification
        
        # Try with SSL verification first
        try:
            response = session.get(url, timeout=5)
        except requests.exceptions.SSLError:
            # If SSL verification fails, try without verification as fallback
            session.verify = False
            response = session.get(url, timeout=5)
        
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
    except:
        return set()

def extract_links_selenium(url):
    try:
        options = Options()
        options.headless = True
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(2)

        links = set()
        for elem in driver.find_elements("xpath", "//*[@href or @src]"):
            attr = elem.get_attribute("href") or elem.get_attribute("src")
            if attr:
                links.add(attr)

        # Check for popup alerts
        popup = False
        try:
            driver.switch_to.alert
            popup = True
        except:
            pass

        redirects = driver.execute_script("return window.performance.getEntriesByType('navigation')")
        driver.quit()

        return links, popup, redirects
    except Exception as e:
        print("[-] Selenium Error:", e)
        return set(), False, []

def analyze_url(url):
    print(f"\n🔎 Analyzing: {url}")
    domain = get_domain(url)

    ssl_info = get_ssl_certificate_info(domain)
    ip_info = get_ip_info(domain)

    static_links = extract_links_bs4(url)
    dynamic_links, popup_found, redirects = extract_links_selenium(url)

    all_links = static_links.union(dynamic_links)

    print("\n✅ SSL Certificate Info:")
    print(json.dumps(ssl_info, indent=2))

    print("\n🌍 IP & Location Info:")
    print(json.dumps(ip_info, indent=2))

    print(f"\n🧾 Total Links Found: {len(all_links)}")
    for i, link in enumerate(sorted(all_links), start=1):
        print(f"{i}. {link}")

    print(f"\n⚠️ Popup Found: {'Yes' if popup_found else 'No'}")
    print(f"🔁 Redirection Chain Count: {len(redirects)}")

if __name__ == "__main__":
    input_url = "https://bsnlmobiletower.in/"
    analyze_url(input_url)
