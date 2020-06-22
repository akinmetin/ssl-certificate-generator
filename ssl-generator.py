import sys
from OpenSSL import crypto, SSL


# get arguments except file name
argv = sys.argv[1:]

# define local variables from parsed arguments
email = str(sys.argv[1])
domainName = str(sys.argv[2])
countryName = str(sys.argv[3])
localityName = str(sys.argv[4])
stateName = str(sys.argv[5])
organizationName = str(sys.argv[6])
organizationUnitName = str(sys.argv[7])

serialNumber = 0
validityStartInSeconds = 0
validityEndInSeconds = 10*365*24*60*60
KEY_FILE = "{}.key".format(domainName.split(".")[0])
CERT_FILE = "{}.crt".format(domainName.split(".")[0])

def generate():
    # create a key pair
    k = crypto.PKey()
    
    # 4096 bit RSA key
    k.generate_key(crypto.TYPE_RSA, 4096)

    # generate self-signed certificate
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = domainName
    cert.get_subject().emailAddress = email
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


generate()

# python create ssl certificate --> https://stackoverflow.com/questions/27164354/create-a-self-signed-x509-certificate-in-python