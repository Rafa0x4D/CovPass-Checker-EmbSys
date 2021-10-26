#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import os
import sys
import zlib
import argparse
import logging
from typing import Dict, Tuple, Optional

import cv2

import PIL.Image
import pyzbar.pyzbar

import json
import base45
import base64
import cbor2
from cose.headers import Algorithm, KID
from cose.messages import CoseMessage
from cose.keys import cosekey, ec2, keyops, keyparam, curves, keytype
from cose import algorithms

from cryptography import x509
from cryptography import hazmat
from pyasn1.codec.ber import decoder as asn1_decoder
from cryptojwt import jwk as cjwtk
from cryptojwt import utils as cjwt_utils

log = logging.getLogger(__name__)

DEFAULT_CERTIFICATE_DB_JSON = 'certs/roots/Digital_Green_Certificate_Signing_Keys.json'
DEFAULT_CERTIFICATE_DIRECTORY = 'certs'


def _setup_logger() -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    logging.getLogger().addHandler(console_handler)
    # log.setLevel(logging.DEBUG)
    log.setLevel(logging.INFO)


def find_key(key: KID, keys_file: str) -> Optional[cosekey.CoseKey]:
    if False:
        # Test read a PEM-key
        cose_key = read_cosekey_from_pem_file("certs/Finland.pem")
        # pprint(cose_key)
        # pprint(cose_key.kid.decode())

    key_id_str = key.hex()
    pem_filename = "{}/{}.pem".format(DEFAULT_CERTIFICATE_DIRECTORY, key_id_str)
    log.debug("Check if certificate {} exists.".format(pem_filename))
    if os.path.exists(pem_filename):
        with open(pem_filename, "rb") as pem_file:
            lines = pem_file.read()
        cert = x509.load_pem_x509_certificate(lines)
        try:
            subject = cert.subject
        except ValueError:
            subject = None
        if subject:
            subject_parts = []
            for subject_compo in subject:
                subject_parts.append("{} = {}".format(subject_compo.oid._name, subject_compo.value))
            log.debug("Certificate subject: {}".format(', '.join(subject_parts)))
        else:
            log.debug("Certificate has no subject")
        log.info("Using certificate {}".format(pem_filename))
        cose_key = _cert_to_cose_key(cert, key)
    else:
        # Read the JSON-database of all known keys
        with open(keys_file, encoding='utf-8') as f:
            known_keys = json.load(f)

        cose_key = None
        for key_id, key_data in known_keys.items():
            key_id_binary = base64.b64decode(key_id)
            if key_id_binary == key:
                log.info("Found the key from DB!")
                # pprint(key_data)
                # check if the point is uncompressed rather than compressed
                x, y = public_ec_key_points(base64.b64decode(key_data['publicKeyPem']))
                key_dict = {'crv': key_data['publicKeyAlgorithm']['namedCurve'],  # 'P-256'
                            'kid': key_id_binary.hex(),
                            'kty': key_data['publicKeyAlgorithm']['name'][:2],  # 'EC'
                            'x': x,  # 'eIBWXSaUgLcxfjhChSkV_TwNNIhddCs2Rlo3tdD671I'
                            'y': y,  # 'R1XB4U5j_IxRgIOTBUJ7exgz0bhen4adlbHkrktojjo'
                            }
                cose_key = cosekey_from_jwk_dict(key_dict)
                break

        if not cose_key:
            return None

    if cose_key.kid.decode() != key.hex():
        raise RuntimeError("Internal: No key for {0}!".format(key.hex()))

    return cose_key


def _cert_to_cose_key(cert: x509.Certificate, key_id: KID = None) -> cosekey.CoseKey:
    public_key = cert.public_key()
    key_dict = None

    if isinstance(public_key, hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        matching_curve = None
        for name in dir(curves):
            if name.startswith('_'):
                continue
            if curve_name.lower() == name.lower():
                if name == 'SECP256R1':
                    matching_curve = curves.P256
                elif name == 'SECP384R1':
                    matching_curve = curves.P384
                else:
                    raise RuntimeError("Unknown curve {}!".format(curve_name))
                break

        if not matching_curve:
            raise RuntimeError("Could not find curve {} used in X.509 certificate from COSE!".format(curve_name))

        public_numbers = public_key.public_numbers()
        size_bytes = public_key.curve.key_size // 8
        x = public_numbers.x.to_bytes(size_bytes, byteorder="big")
        y = public_numbers.y.to_bytes(size_bytes, byteorder="big")
        key_dict = {
            keyparam.KpKeyOps: [keyops.VerifyOp],
            keyparam.KpKty: keytype.KtyEC2,
            keyparam.EC2KpCurve: matching_curve,
            keyparam.KpAlg: algorithms.Es256,
            keyparam.EC2KpX: x,
            keyparam.EC2KpY: y,
            keyparam.KpKid: bytes(key_id.hex(), "ASCII")
        }
    else:
        raise RuntimeError("Cannot handle RSA-keys!")

    key = cosekey.CoseKey.from_dict(key_dict)

    return key


def public_ec_key_points(public_key: bytes) -> Tuple[str, str]:
    # This code adapted from: https://stackoverflow.com/a/59537764/1548275
    public_key_asn1, _remainder = asn1_decoder.decode(public_key)
    public_key_bytes = public_key_asn1[1].asOctets()

    off = 0
    if public_key_bytes[off] != 0x04:
        raise ValueError("EC public key is not an uncompressed point")
    off += 1

    size_bytes = (len(public_key_bytes) - 1) // 2

    x_bin = public_key_bytes[off:off + size_bytes]
    x = int.from_bytes(x_bin, 'big', signed=False)
    off += size_bytes

    y_bin = public_key_bytes[off:off + size_bytes]
    y = int.from_bytes(y_bin, 'big', signed=False)
    off += size_bytes

    bl = (x.bit_length() + 7) // 8
    bytes_val = x.to_bytes(bl, 'big')
    x_str = base64.b64encode(bytes_val, altchars='-_'.encode()).decode()

    bl = (y.bit_length() + 7) // 8
    bytes_val = y.to_bytes(bl, 'big')
    y_str = base64.b64encode(bytes_val, altchars='-_'.encode()).decode()

    return x_str, y_str


# Create CoseKey from JWK
def cosekey_from_jwk_dict(jwk_dict: Dict) -> cosekey.CoseKey:
    # Read key and return CoseKey
    if jwk_dict["kty"] != "EC":
        raise ValueError("Only EC keys supported")
    if jwk_dict["crv"] != "P-256":
        raise ValueError("Only P-256 supported")

    from pprint import pprint
    key = ec2.EC2(
        crv=curves.P256,
        x=cjwt_utils.b64d(jwk_dict["x"].encode()),
        y=cjwt_utils.b64d(jwk_dict["y"].encode()),
    )
    key.key_ops = [keyops.VerifyOp]
    if "kid" in jwk_dict:
        key.kid = bytes(jwk_dict["kid"], "UTF-8")

    return key


# Create JWK and valculate KID from Public Signing Certificate
def read_cosekey_from_pem_file(cert_file: str) -> cosekey.CoseKey:
    # Read certificate, calculate kid and return EC CoseKey
    if not cert_file.endswith(".pem"):
        raise ValueError("Unknown key format. Use .pem keyfile")

    with open(cert_file, 'rb') as f:
        cert_data = f.read()
        # Calculate Hash from the DER format of the Certificate
        cert = x509.load_pem_x509_certificate(cert_data, hazmat.backends.default_backend())
        keyidentifier = cert.fingerprint(hazmat.primitives.hashes.SHA256())
    f.close()
    key = cert.public_key()

    jwk = cjwtk.ec.ECKey()
    jwk.load_key(key)
    # Use first 8 bytes of the hash as Key Identifier (Hex as UTF-8)
    jwk.kid = keyidentifier[:8].hex()
    jwk_dict = jwk.serialize(private=False)

    return cosekey_from_jwk_dict(jwk_dict)


def output_covid_cert_data(cert: str, keys_file: str) -> None:
    # Code adapted from:
    # https://alphalist.com/blog/the-use-of-blockchain-for-verification-eu-vaccines-passport-program-and-more

    # Strip the first characters to form valid Base45-encoded data
    b45data = cert[4:]

    # Decode the data
    zlibdata = base45.b45decode(b45data)

    # Uncompress the data
    decompressed = zlib.decompress(zlibdata)

    # decode COSE message (no signature verification done)
    cose_msg = CoseMessage.decode(decompressed)
    # pprint.pprint(cose_msg)

    # decode the CBOR encoded payload and print as json
    log.debug(cose_msg.phdr)
    if KID in cose_msg.uhdr:
        log.info("COVID certificate signed with X.509 certificate.")
        log.info("X.509 in DER form has SHA-256 beginning with: {0}".format(
            cose_msg.uhdr[KID].hex()))
        key = find_key(cose_msg.uhdr[KID], keys_file)
        if key:
            verify_signature(cose_msg, key)
        else:
            log.info("Skip verify as no key found from database")
    else:
        log.info("Certificate is not signed")
    # log.debug(cose_msg.uhdr)
    # log.debug(cose_msg.key)
    cbor = cbor2.loads(cose_msg.payload)
    # Note: Some countries have hour:minute:secod for sc-field (Date/Time of Sample Collection).
    # If used, this will decode as a datetime. A datetime cannot be JSON-serialized without hints (use str as default).
    # Note 2: Names may contain non-ASCII characters in UTF-8
    log.info("Certificate as JSON: {0}".format(json.dumps(cbor, indent=2, default=str, ensure_ascii=False)))


def verify_signature(cose_msg: CoseMessage, key: cosekey.CoseKey) -> bool:
    cose_msg.key = key
    if not cose_msg.verify_signature():
        log.warning("Signature does not verify with key ID {0}!".format(key.kid.decode()))
        return False

    log.info("Signature verified ok")

    return cose_msg.verify_signature()


def main() -> None:
    parser = argparse.ArgumentParser(description='EU COVID Vaccination Passport Verifier')
    parser.add_argument('--image-file', metavar="IMAGE-FILE",
                        help='Image to read QR-code from')
    parser.add_argument('--raw-string', metavar="RAW-STRING",
                        help='Contents of the QR-code as string')
    parser.add_argument('image_file_positional', metavar="IMAGE-FILE", nargs="?",
                        help='Image to read QR-code from')
    parser.add_argument('--certificate-db-json-file', default=DEFAULT_CERTIFICATE_DB_JSON,
                        help="Default: {0}".format(DEFAULT_CERTIFICATE_DB_JSON))

    args = parser.parse_args()
    _setup_logger()

    covid_cert_data = None
    image_file = None
    if args.image_file_positional:
        image_file = args.image_file_positional
    elif args.image_file:
        image_file = args.image_file

    if image_file:
        data = pyzbar.pyzbar.decode(PIL.Image.open(image_file))
        covid_cert_data = data[0].data.decode()
    elif args.raw_string:
        covid_cert_data = args.raw_string
    else:
        log.error("Input parameters: Need either --image-file or --raw-string QR-code content.")
        exit(2)

    # Got the data, output
    log.debug("Cert data: '{0}'".format(covid_cert_data))
    output_covid_cert_data(covid_cert_data, args.certificate_db_json_file)

def videocapture(cap):
    parser = argparse.ArgumentParser(description='EU COVID Vaccination Passport Verifier')
    parser.add_argument('--image-file', metavar="IMAGE-FILE",
                        help='Image to read QR-code from')
    parser.add_argument('--raw-string', metavar="RAW-STRING",
                        help='Contents of the QR-code as string')
    parser.add_argument('image_file_positional', metavar="IMAGE-FILE", nargs="?",
                        help='Image to read QR-code from')
    parser.add_argument('--certificate-db-json-file', default=DEFAULT_CERTIFICATE_DB_JSON,
                        help="Default: {0}".format(DEFAULT_CERTIFICATE_DB_JSON))

    args = parser.parse_args()

    vid = cap

    log.info('started capturing')

    while True:
        ret, frame = vid.read()

        height = int(vid.get(4))

        cert_info = ["Waiting for QR-Codes..."]
        
        barcodes = pyzbar.pyzbar.decode(frame)

        if not barcodes:
            log.info('no barcode detected')
        
        data = pyzbar.pyzbar.decode(frame)

        for barcode in barcodes:
            covid_cert_data = barcode.data.decode()

            # Strip the first characters to form valid Base45-encoded data
            b45data = covid_cert_data[4:]

            # Decode the data
            zlibdata = base45.b45decode(b45data)

            # Uncompress the data
            decompressed = zlib.decompress(zlibdata)

            # decode COSE message (no signature verification done)
            cose_msg = CoseMessage.decode(decompressed)

            # decode the CBOR encoded payload and print as json
            key_verified = False
            if KID in cose_msg.uhdr:
                log.info("COVID certificate signed with X.509 certificate.")
                log.info("X.509 in DER form has SHA-256 beginning with: {0}".format(
                    cose_msg.uhdr[KID].hex()))
                key = find_key(cose_msg.uhdr[KID], args.certificate_db_json_file)
                if key:
                    key_verified = verify_signature(cose_msg, key)
                else:
                    log.info("Skip verify as no key found from database")
            else:
                log.info("Certificate is not signed")

            cbor = cbor2.loads(cose_msg.payload)

            # log.debug("Cert data: '{0}'".format(covid_cert_data))
            # output_covid_cert_data(covid_cert_data, args.certificate_db_json_file)

            # data to display
            cert_info = [
                    cbor[-260][1]['nam']['fn'] + " " + cbor[-260][1]['nam']['gn'],
                    str(cbor[-260][1]['v'][0]['dn']) + " von " + str(cbor[-260][1]['v'][0]['sd']) + " Impfungen erhalten"
                ]
            
            borderColor = (0, 0, 255)
            if key_verified:
                cert_info.append("Signature Verified")
                borderColor = (0, 255, 0)
            else:
                cert_info.append("Certificate Invalid")

            # Draw rectangle around barcode
            (x, y, w, h) = barcode.rect
            cv2.rectangle(frame, (x, y), (x + w, y + h), borderColor, 10)
        
        offset = 0
        # Put Data to Frame to display the data       
        for itr, word in enumerate(cert_info):
            offset += int(height / len(cert_info)) - 10
            frame = cv2.putText(frame, word, 
                                        (20, offset), # Point = Bottom-left corner of the Text String
                                        cv2.FONT_HERSHEY_SIMPLEX, # Font type
                                        0.5, # Font Scale (size)
                                        (35, 252, 20), # Color
                                        1, # Tickness
                                        cv2.LINE_AA # Line Type
        )

        ret, jpeg = cv2.imencode(".jpeg", frame)
        frame = jpeg.tobytes()

        yield(b'--frame\r\n'
              b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')


if __name__ == '__main__':
    capturevideo()
