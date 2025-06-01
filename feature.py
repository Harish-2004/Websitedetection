import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
import dns.resolver
import warnings
import urllib3

# Suppress all warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            # Create a session with proper SSL verification
            session = requests.Session()
            session.verify = True  # Enable SSL verification
            
            # Try with SSL verification first
            try:
                self.response = session.get(self.url, timeout=5)
            except requests.exceptions.SSLError:
                # If SSL verification fails, try without verification as fallback
                session.verify = False
                self.response = session.get(self.url, timeout=5)
            
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=UserWarning)
                self.soup = BeautifulSoup(self.response.text, 'lxml')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        # Extract features in the exact order expected by URLAnalyzer
        self.features.append(self.UsingIP())          # 1. UsingIP
        self.features.append(self.LongURL())          # 2. LongURL
        self.features.append(self.ShortURL())         # 3. ShortURL
        self.features.append(self.Symbol())           # 4. Symbol@
        self.features.append(self.Redirecting())      # 5. Redirecting//
        self.features.append(self.PrefixSuffix())     # 6. PrefixSuffix-
        self.features.append(self.SubDomains())       # 7. SubDomains
        self.features.append(self.HTTPS())            # 8. HTTPS
        self.features.append(self.DomainRegLen())     # 9. DomainRegLen
        self.features.append(self.Favicon())          # 10. Favicon
        self.features.append(self.NonStdPort())       # 11. NonStdPort
        self.features.append(self.HTTPSDomainURL())   # 12. HTTPSDomainURL
        self.features.append(self.RequestURL())       # 13. RequestURL
        self.features.append(self.AnchorURL())        # 14. AnchorURL
        self.features.append(self.LinksInScriptTags()) # 15. LinksInScriptTags
        self.features.append(self.ServerFormHandler()) # 16. ServerFormHandler
        self.features.append(self.InfoEmail())        # 17. InfoEmail
        self.features.append(self.AbnormalURL())      # 18. AbnormalURL
        self.features.append(self.WebsiteForwarding()) # 19. WebsiteForwarding
        self.features.append(self.StatusBarCust())    # 20. StatusBarCust
        self.features.append(self.DisableRightClick()) # 21. DisableRightClick
        self.features.append(self.UsingPopupWindow()) # 22. UsingPopupWindow
        self.features.append(self.IframeRedirection()) # 23. IframeRedirection
        self.features.append(self.AgeofDomain())      # 24. AgeofDomain
        self.features.append(self.DNSRecording())     # 25. DNSRecording
        self.features.append(self.WebsiteTraffic())   # 26. WebsiteTraffic
        self.features.append(self.PageRank())         # 27. PageRank
        self.features.append(self.GoogleIndex())      # 28. GoogleIndex
        self.features.append(self.LinksPointingToPage()) # 29. LinksPointingToPage
        self.features.append(self.StatsReport())      # 30. StatsReport

    # 1.UsingIP
    def UsingIP(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.LongURL
    def LongURL(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.ShortURL
    def ShortURL(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4.Symbol@
    def Symbol(self):
        if re.findall("@",self.url):
            return -1
        return 1
    
    # 5.Redirecting//
    def Redirecting(self):
        if self.url.rfind('//')>6:
            return -1
        return 1
    
    # 6.PrefixSuffix-
    def PrefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count<4:
            return 1
        elif dot_count>=4 and dot_count<=6:
            return 0
        else:
            return -1

    # 8.HTTPS
    def HTTPS(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
            if age >=12:
                return 1
            return -1
        except:
            return -1

    # 10.Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11.NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port)>1:
                return -1
            return 1
        except:
            return -1

    # 12.HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1
    
    # 13.RequestURL
    def RequestURL(self):
        try:
            success = 0
            i = 0
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success/float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1
    
    # 14.AnchorURL
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1

        except:
            return -1

    # 15.LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i,success = 0,0
        
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif((percentage >= 17.0) and (percentage < 81.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16.ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return 1
            else :
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17.InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soap):
                return -1
            else:
                return 1
        except:
            return -1

    # 18.AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19.WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
             return -1

    # 20.StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 21.DisableRightClick
    def DisableRightClick(self):
        try:
            # Check for common right-click disable patterns
            patterns = [
                r"event\.button\s*==\s*2",  # Right click event
                r"oncontextmenu\s*=\s*['\"]return false['\"]",  # Context menu disable
                r"document\.oncontextmenu\s*=\s*function\(\)\s*{\s*return false",  # Context menu function
                r"addEventListener\s*\(\s*['\"]contextmenu['\"]",  # Context menu listener
                r"preventDefault\s*\(\s*\)",  # Event prevention
                r"return false;",  # Generic return false
                r"e\.preventDefault\s*\(\s*\)"  # Event prevention with parameter
            ]
            
            # Check if any pattern matches
            for pattern in patterns:
                if re.search(pattern, self.response.text, re.IGNORECASE):
                    return -1
            return 1
        except:
            return 0  # Return neutral on error instead of suspicious

    # 22.UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if not self.response.text:
                return 0
            
            # Common popup patterns
            popup_patterns = [
                r"alert\s*\(",  # Basic alert
                r"confirm\s*\(",  # Confirmation dialog
                r"prompt\s*\(",  # Input prompt
                r"window\.open\s*\(",  # Window.open
                r"showModalDialog\s*\(",  # Modal dialog
                r"createPopup\s*\(",  # IE popup
                r"showModal\s*\(",  # Modal
                r"\.modal\s*\(",  # Bootstrap modal
                r"\.dialog\s*\(",  # jQuery dialog
                r"\.popup\s*\(",  # Generic popup
                r"onbeforeunload\s*=",  # Before unload
                r"onunload\s*=",  # Unload
                r"data-toggle=['\"]modal['\"]",  # Bootstrap data attribute
                r"class=['\"][^'\"]*modal[^'\"]*['\"]"  # Modal class
            ]
            
            popup_count = 0
            for pattern in popup_patterns:
                matches = len(re.findall(pattern, self.response.text, re.IGNORECASE))
                popup_count += matches
            
            # Evaluate based on number of popup patterns found
            if popup_count == 0:
                return 1  # No popups found
            elif popup_count <= 2:
                return 0  # Few popups, might be legitimate
            else:
                return -1  # Multiple popups, suspicious
        except:
            return 0  # Return neutral on error

    # 23.IframeRedirection
    def IframeRedirection(self):
        try:
            if not self.soup:
                return 0
            
            # Check for iframes
            iframes = self.soup.find_all('iframe')
            if not iframes:
                return 1  # No iframes found, considered safe
            
            suspicious_count = 0
            total_iframes = len(iframes)
            
            for iframe in iframes:
                # Check for suspicious attributes
                src = iframe.get('src', '').lower()
                style = iframe.get('style', '').lower()
                
                # Suspicious patterns
                suspicious_patterns = [
                    'hidden', 'display:none', 'visibility:hidden',
                    'opacity:0', 'width:0', 'height:0',
                    'position:absolute', 'position:fixed',
                    'z-index:-1', 'left:-9999px'
                ]
                
                # Check for suspicious sources
                if any(pattern in src for pattern in ['redirect', 'login', 'verify', 'secure']):
                    suspicious_count += 1
                
                # Check for suspicious styling
                if any(pattern in style for pattern in suspicious_patterns):
                    suspicious_count += 1
            
            # Evaluate based on ratio of suspicious iframes
            if total_iframes == 0:
                return 1
            elif suspicious_count / total_iframes > 0.5:  # More than 50% suspicious
                return -1
            elif suspicious_count / total_iframes > 0.2:  # 20-50% suspicious
                return 0
            else:
                return 1
        except:
            return 0  # Return neutral on error

    # 24.AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if not creation_date:
                return 0  # Return neutral if no creation date
            
            # Handle both single date and list of dates
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            today = date.today()
            age_months = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            
            # More granular age classification
            if age_months >= 24:  # 2 years or more
                return 1
            elif age_months >= 12:  # 1-2 years
                return 0
            else:  # Less than 1 year
                return -1
        except:
            return 0  # Return neutral on error

    # 25.DNSRecording
    def DNSRecording(self):
        try:
            # Check multiple DNS record types
            domain = self.domain
            if not domain:
                return 0
            
            # Check for common DNS records
            records_to_check = ['A', 'AAAA', 'MX', 'NS', 'TXT']
            valid_records = 0
            
            for record_type in records_to_check:
                try:
                    dns.resolver.resolve(domain, record_type)
                    valid_records += 1
                except:
                    continue
            
            # More granular scoring based on number of valid records
            if valid_records >= 4:  # Most records present
                return 1
            elif valid_records >= 2:  # Some records present
                return 0
            else:  # Few or no records
                return -1
        except:
            return 0  # Return neutral on error

    # 26.WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            domain = self.domain
            if not domain:
                return 0
            
            # Remove www. if present
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Method 1: Check Google Indexing and Search Results
            try:
                from googlesearch import search
                # Check if site is indexed by Google and has multiple pages
                indexed_pages = list(search(f"site:{domain}", num=5, stop=5))
                if len(indexed_pages) > 0:
                    if len(indexed_pages) >= 3:
                        return 1  # Multiple pages indexed, likely has good traffic
                    return 0  # At least one page indexed
            except:
                pass
            
            # Method 2: Check DNS records for common CDNs and services
            try:
                import dns.resolver
                # Check for common CDN and service records
                cdn_indicators = [
                    'cloudfront.net', 'akamai.net', 'fastly.net',
                    'cloudflare.com', 'azureedge.net', 'googleusercontent.com',
                    'amazonaws.com', 'azure.com', 'google.com'
                ]
                
                # Check A and CNAME records
                try:
                    a_records = dns.resolver.resolve(domain, 'A')
                    for record in a_records:
                        if any(cdn in str(record) for cdn in cdn_indicators):
                            return 1  # Using CDN, likely has some traffic
                except:
                    pass
                    
                try:
                    cname_records = dns.resolver.resolve(domain, 'CNAME')
                    for record in cname_records:
                        if any(cdn in str(record) for cdn in cdn_indicators):
                            return 1  # Using CDN, likely has some traffic
                except:
                    pass
            except:
                pass
            
            # Method 3: Check for common analytics and tracking scripts
            try:
                analytics_scripts = [
                    'google-analytics.com/ga.js',
                    'google-analytics.com/analytics.js',
                    'googletagmanager.com/gtag/js',
                    'matomo.js',
                    'piwik.js',
                    'analytics.js',
                    'gtag.js',
                    'ga.js',
                    'fbq.js',  # Facebook Pixel
                    'linkedin.com/analytics',
                    'twitter.com/analytics'
                ]
                
                if any(script in self.response.text for script in analytics_scripts):
                    return 1  # Has analytics, likely has some traffic
            except:
                pass
            
            # Method 4: Check for social media presence and sharing buttons
            try:
                social_indicators = [
                    'facebook.com', 'twitter.com', 'linkedin.com',
                    'instagram.com', 'youtube.com', 'pinterest.com',
                    'sharethis.com', 'addthis.com', 'share-buttons',
                    'social-share', 'social-media-icons'
                ]
                
                if any(indicator in self.response.text for indicator in social_indicators):
                    return 0  # Has social media links, might have some traffic
            except:
                pass
            
            # Method 5: Check for common e-commerce and business indicators
            try:
                business_indicators = [
                    'shopping-cart', 'add-to-cart', 'checkout',
                    'payment-methods', 'customer-reviews',
                    'product-reviews', 'trust-badges',
                    'secure-checkout', 'ssl-secured'
                ]
                
                if any(indicator in self.response.text.lower() for indicator in business_indicators):
                    return 1  # Has e-commerce features, likely has traffic
            except:
                pass
            
            # If none of the above methods found significant traffic indicators
            return -1
            
        except:
            return 0  # Return neutral on error

    # 27.PageRank
    def PageRank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})

            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                return 1
            return -1
        except:
            return -1

    # 28.GoogleIndex
    def GoogleIndex(self):
        try:
            from googlesearch import search
            from urllib.parse import urlparse
            
            # Get domain without www
            domain = self.domain
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check multiple search queries
            queries = [
                f"site:{domain}",
                f"inurl:{domain}",
                f"intitle:{domain}"
            ]
            
            indexed_pages = set()
            for query in queries:
                try:
                    results = list(search(query, num=5, stop=5))
                    indexed_pages.update(results)
                except:
                    continue
            
            if len(indexed_pages) >= 3:  # Multiple pages indexed
                return 1
            elif len(indexed_pages) > 0:  # At least one page indexed
                return 0
            else:  # No pages indexed
                return -1
        except:
            return 0  # Return neutral on error

    # 29.LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            if not self.soup:
                return 0
            
            # Initialize counters
            internal_links = 0
            external_links = 0
            suspicious_links = 0
            
            # Get all links
            for link in self.soup.find_all('a', href=True):
                href = link['href'].lower()
                
                # Skip empty or javascript links
                if not href or href.startswith(('javascript:', '#')):
                    continue
                
                # Check if it's an internal link
                if self.domain in href or href.startswith('/'):
                    internal_links += 1
                else:
                    external_links += 1
                
                # Check for suspicious link patterns
                suspicious_patterns = [
                    'download', 'click', 'redirect', 'login',
                    'signup', 'register', 'verify', 'confirm',
                    'password', 'account', 'secure', 'update'
                ]
                
                if any(pattern in href for pattern in suspicious_patterns):
                    suspicious_links += 1
            
            # Calculate ratios
            total_links = internal_links + external_links
            if total_links == 0:
                return 0  # No links found, return neutral
            
            suspicious_ratio = suspicious_links / total_links
            external_ratio = external_links / total_links
            
            # Evaluate based on multiple factors
            if total_links < 5:
                return 0  # Too few links to make a determination
            
            if suspicious_ratio > 0.5:  # More than 50% suspicious links
                return -1
            elif suspicious_ratio > 0.2:  # 20-50% suspicious links
                return 0
            elif external_ratio > 0.8:  # More than 80% external links
                return -1
            elif external_ratio > 0.5:  # 50-80% external links
                return 0
            else:
                return 1  # Good balance of internal and external links
            
        except:
            return 0  # Return neutral on error

    # 30.StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1

    def getFeaturesList(self):
        # Create a mapping of method names to expected feature names
        feature_names = [
            'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
            'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
            'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
            'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
        ]
        
        # Return a dictionary with the expected feature names
        return dict(zip(feature_names, self.features))
