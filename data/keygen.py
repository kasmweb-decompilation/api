# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: data/keygen.py
import datetime
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def generate_ssh_keys(public_exponent=65537, key_size=2048):
    key = rsa.generate_private_key(backend=(crypto_default_backend()),
      public_exponent=public_exponent,
      key_size=key_size)
    private_key = key.private_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PrivateFormat.TraditionalOpenSSL, crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH)
    return (
     private_key.decode("utf-8"), public_key.decode("utf-8"))


def generate_ssl_certs(domain_name, ca_cert_pem=None, ca_key_pem=None, days=365):
    if ca_cert_pem is None or ca_key_pem is None:
        root_key = rsa.generate_private_key(public_exponent=3,
          key_size=2048,
          backend=(crypto_default_backend()))
        subject = issuer = x509.Name([
         x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Virginia"),
         x509.NameAttribute(NameOID.LOCALITY_NAME, "McLean"),
         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kasm Technologies"),
         x509.NameAttribute(NameOID.COMMON_NAME, domain_name)])
        root_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(root_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650)).sign(root_key, hashes.SHA256(), crypto_default_backend())
        cert_pem = root_cert.public_bytes(encoding=(crypto_serialization.Encoding.PEM)).decode("utf-8")
        cert_key_pem = root_key.private_bytes(encoding=(crypto_serialization.Encoding.PEM),
          format=(crypto_serialization.PrivateFormat.TraditionalOpenSSL),
          encryption_algorithm=(crypto_serialization.NoEncryption()))
    else:
        root_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), crypto_default_backend())
        root_key = crypto_serialization.load_pem_private_key((bytes(ca_key_pem, "utf-8")), unsafe_skip_rsa_key_validation=False)
        cert_key = rsa.generate_private_key(public_exponent=3,
          key_size=2048,
          backend=(crypto_default_backend()))
        new_subject = x509.Name([
         x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Virginia"),
         x509.NameAttribute(NameOID.LOCALITY_NAME, "McLean"),
         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kasm Technologies"),
         x509.NameAttribute(NameOID.COMMON_NAME, domain_name)])
        cert = x509.CertificateBuilder().subject_name(new_subject).issuer_name(root_cert.issuer).public_key(cert_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days)).add_extension((x509.SubjectAlternativeName([x509.DNSName(domain_name)])),
          critical=False).sign(root_key, hashes.SHA256(), crypto_default_backend())
        cert_pem = cert.public_bytes(encoding=(crypto_serialization.Encoding.PEM),
          format=(serialization.PublicFormat.SubjectPublicKeyInfo)).decode("utf-8")
        cert_key_pem = cert_key.private_bytes(encoding=(crypto_serialization.Encoding.PEM),
          format=(crypto_serialization.PrivateFormat.TraditionalOpenSSL),
          encryption_algorithm=(crypto_serialization.NoEncryption()))
    return (
     cert_key_pem, cert_pem)

# okay decompiling bytecode/data/keygen.pyc
