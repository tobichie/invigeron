# The CA must create a certificate and self sign it.
# It must then be able to receive client certificates and sign it
# However it must only be signed if the certificate does not
# use a name that is in use.
# Cant sign a cert with the name 'client' if there is already a cert
# with the name client
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
import uuid

class CA:
    def __init__(self):
        return

    def create_and_self_sign_cert(self):

        # first create RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend() # this uses the openssl backend
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Califionie"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wu-Tang-Clan"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Franciscee"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Ty-CA"),
        ])
        # next we need to generate a unique serial number which is 0 < i < 2^160
        serial_number = x509.random_serial_number()
        # next we set the certificates validity
        valid_from = datetime.now(timezone.utc)
        valid_to = valid_from + timedelta(days=365)
        # next up, build the cert
        certificate_builder = x509.CertificateBuilder().subject_name(
            subject # this means the certificate if made for the subject
        ).issuer_name(
            issuer # this means the certificate is issued by the issuer
            # the issuer is also subject, making this a self signed certificate
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            valid_from
        ).not_valid_after(
            valid_to
        )
        # Sign the certificate with the private key (use SHA256 hash algorithm)
        certificate = certificate_builder.sign(
            private_key = private_key,
            algorithm = hashes.SHA256(),
            backend = default_backend()
        )

        # Save the private key to a PEM file (unencrypted for simplicity)
        with open("./ca/private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,  # Modern format for private keys
                encryption_algorithm=serialization.NoEncryption()  # No password (insecure for production!)
            ))

            # Save the certificate to a PEM file
        with open("./ca/certificate.pem", "wb") as f:
            f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
        return

    def csr(self, subject, client_public_key):
        # use the self signed x.509 cert to make, sign and send the cert
        # get the ca certificate to get the issuer
        with open("./ca/certificate.pem", "rb") as f:
            ca_certificate = x509.load_pem_x509_certificate(f.read())
        with open("./ca/private_key.pem", "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        valid_from = datetime.now(timezone.utc)
        valid_to = valid_from + timedelta(days=365)
        # start building the client certificate
        builder = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(ca_certificate.subject) \
            .public_key(client_public_key) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(valid_from) \
            .not_valid_after(valid_to)
        # sign the client certificate using the ca private key
        client_certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256()
        )
        return client_certificate



def test():
    # teste below
    ca = CA()
    # make a public key for testing
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend() # this uses the openssl backend
    )
    public_key = private_key.public_key()
    # ca.create_and_self_sign_cert()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Califionie"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Start Ind."),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Nordrhein"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Ty-Client"),
    ])
    client_certificate = ca.csr(subject, public_key)
    # write the client cert for test
    print(
        client_certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()
    )
    print("Subject:", client_certificate.subject)
    print("Issuer:", client_certificate.issuer)
    print("Serial Number:", client_certificate.serial_number)
    print("Valid From:", client_certificate.not_valid_before_utc)
    print("Valid Until:", client_certificate.not_valid_after_utc)
    print("Public Key:", client_certificate.public_key())
    print("Signature Algorithm:", client_certificate.signature_algorithm_oid)
    return

if __name__ == "__main__":
    test()