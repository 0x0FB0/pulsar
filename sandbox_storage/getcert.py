import ssl
import OpenSSL
import sys

cn = 'no-certificate-error'
try:
    cert = ssl.get_server_certificate((str(sys.argv[1]),443))
    subject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).get_subject()
    for comp in subject.get_components():
        if b'CN' in comp:
            cn = comp[1].decode('utf-8')
except Exception as e:
    print(repr(e))
    pass

print(cn)
