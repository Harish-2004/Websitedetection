import ssl, socket

def has_valid_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return 1
    except Exception:
        return 0
import ssl
import OpenSSL

def has_valid_ssl(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        issuer = x509.get_issuer()
        not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        days_to_expire = (not_after - datetime.utcnow()).days
        return 1 if days_to_expire > 30 else 0  # Trust if >30 days
    except:
        return 0
