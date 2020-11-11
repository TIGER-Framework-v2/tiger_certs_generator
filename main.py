"""
The script generates server/client key and cert for Docker HTTPS connection.
The next files will be created:
    ca.crt - CA certificate(Needed on server and client side)
    ca.pem - CA private key
    server.key - Private key for server certificate(Needed on server side)
    server.crt - Server certificate(Needed on server side)
    client.key - Client key for server certificate(Needed on client side)
    client.crt - Client certificate(Needed on Client side)
"""

import os
import argparse
from OpenSSL import crypto, SSL
from socket import gethostname, gethostbyname
from time import gmtime, mktime

def create_ca_self_signed_cert():
    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "BY"
    cert.get_subject().ST = "Minsk"
    cert.get_subject().L = "Minsk"
    cert.get_subject().O = "TIGER ltd."
    cert.get_subject().OU = "TIGER ltd."
    cert.get_subject().CN = gethostname() 
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

    ca_cert = cert 
    ca_key = key

    return ca_cert, ca_key


def create_key_csr(common_name, country=None, state=None, city=None, organization=None, organizational_unit=None,email_address=None):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    req = crypto.X509Req()
    req.get_subject().CN = common_name
    if country:
        req.get_subject().C = country
    if state:
        req.get_subject().ST = state
    if city:
        req.get_subject().L = city
    if organization:
        req.get_subject().O = organization
    if organizational_unit:
        req.get_subject().OU = organizational_unit
    if email_address:
        req.get_subject().emailAddress = email_address

    req.set_pubkey(key)
    req.sign(key, 'sha256')

    private_key = key
    csr = req 

    return private_key, csr

def sign_cert(caCert,serverCsr,caKey,serverFlag=None):
    cert = crypto.X509()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(caCert.get_subject())
    cert.set_subject(serverCsr.get_subject())
    cert.set_pubkey(serverCsr.get_pubkey())
    
    if serverFlag:
        # If server flag was given, then add Alt.Names to the cert
        if args.ipaddress:
            alt_ip = args.ipaddress
        else:
            alt_ip = gethostbyname(gethostname())

        alt_names = "DNS:localhost,DNS:{},IP:127.0.0.1,IP:{}".format(args.dnsname,alt_ip)
        cert.add_extensions([
            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
            crypto.X509Extension(b"subjectAltName", False, alt_names.encode('utf-8'))
        ])
    else:
        cert.add_extensions([
            crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth")
        ])

    cert.sign(caKey, 'sha256')
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)


parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('-ip','--ipaddress', type = str, metavar = '', help='IP address of Docker server. Default value: IP from your system')
parser.add_argument('-dns','--dnsname', type = str, metavar = '', required = True, help='DNS name of Docker server')
args = parser.parse_args()

ca_cert, ca_key = create_ca_self_signed_cert()
server_key, server_csr = create_key_csr(gethostname())
client_key, client_csr = create_key_csr("client")
server_cert = sign_cert(ca_cert,server_csr,ca_key,True)
client_cert = sign_cert(ca_cert,client_csr,ca_key)

open("/certs/ca.crt", "wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
open("/certs/ca.pem", "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))

open('/certs/server.key', "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key))
open('/certs/server.crt', 'wb').write(server_cert)

open('/certs/client.key', "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key))
open('/certs/client.crt', 'wb').write(client_cert)
