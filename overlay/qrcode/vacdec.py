#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import os
import sys
import zlib
import argparse
import logging
from datetime import datetime, timedelta
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
    log_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    logging.getLogger().addHandler(console_handler)
    # log.setLevel(logging.DEBUG)
    log.setLevel(logging.INFO)


def find_key(key: KID, keys_file: str) -> Optional[cosekey.CoseKey]:
    key_id_str = key.hex()
    pem_filename = "{}/{}.pem".format(
        DEFAULT_CERTIFICATE_DIRECTORY, key_id_str)
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
                subject_parts.append("{} = {}".format(
                    subject_compo.oid._name, subject_compo.value))
            log.debug("Certificate subject: {}".format(
                ', '.join(subject_parts)))
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
                x, y = public_ec_key_points(
                    base64.b64decode(key_data['publicKeyPem']))
                key_dict = {'crv': key_data['publicKeyAlgorithm']['namedCurve'],  # 'P-256'
                            'kid': key_id_binary.hex(),
                            # 'EC'
                            'kty': key_data['publicKeyAlgorithm']['name'][:2],
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
            raise RuntimeError(
                "Could not find curve {} used in X.509 certificate from COSE!".format(curve_name))

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
        cert = x509.load_pem_x509_certificate(
            cert_data, hazmat.backends.default_backend())
        keyidentifier = cert.fingerprint(hazmat.primitives.hashes.SHA256())
    f.close()
    key = cert.public_key()

    jwk = cjwtk.ec.ECKey()
    jwk.load_key(key)
    # Use first 8 bytes of the hash as Key Identifier (Hex as UTF-8)
    jwk.kid = keyidentifier[:8].hex()
    jwk_dict = jwk.serialize(private=False)

    return cosekey_from_jwk_dict(jwk_dict)

def verify_signature(cose_msg: CoseMessage, key: cosekey.CoseKey) -> bool:
    cose_msg.key = key
    if not cose_msg.verify_signature():
        log.warning(
            "Signature does not verify with key ID {0}!".format(key.kid.decode()))
        return False

    log.info("Signature verified ok")

    return cose_msg.verify_signature()

def drawFrame(frame, message, frame_height, text_color):
    offset = 0
    # Put Data to Frame to display the data
    for itr, word in enumerate(message):
        offset += int(frame_height / len(message)) - 10
        frame = cv2.putText(frame, word,
                            # Point = Bottom-left corner of the Text String
                            (20, offset),
                            cv2.FONT_HERSHEY_SIMPLEX,  # Font type
                            1,  # Font Scale (size)
                            text_color,  # Color
                            1,  # Tickness
                            cv2.LINE_AA  # Line Type
                            )

    ret, jpeg = cv2.imencode(".jpeg", frame)
    frame = jpeg.tobytes()

    return (b'--frame\r\n'
            b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')


def check_fully_vaccinated(cbor):
    nth_dose = str(cbor[-260][1]['v'][0]['dn'])
    total_doses = str(cbor[-260][1]['v'][0]['sd'])
    lastdosedate = str(cbor[-260][1]['v'][0]['dt'])
    lastdosedate = datetime.strptime(lastdosedate, "%Y-%m-%d")
    now = datetime.now()

    return (nth_dose == total_doses) and ((lastdosedate + timedelta(days=15)) > now)


def createMessage(cbor, key_verified):
    firstname = cbor[-260][1]['nam']['fn']
    lastname = cbor[-260][1]['nam']['gn']
    nth_dose = str(cbor[-260][1]['v'][0]['dn'])
    total_doses = str(cbor[-260][1]['v'][0]['sd'])

    message = [
        firstname + " " + lastname,
        nth_dose + " von " + total_doses + " Impfungen erhalten",
        "Signatur gueltig"
    ]

    if not key_verified:
        message = ["Signatur ungueltig"]

    return message


def videocapture(cap):
    color_red = (0, 0, 255)
    color_green = (0, 255, 0)
    text_color = color_green

    log.info('started capturing')

    while True:
        ret, frame = cap.read()

        height = int(cap.get(4))

        cert_info = ["Waiting for QR-Codes..."]

        barcodes = pyzbar.pyzbar.decode(frame)

        if len(barcodes) > 1:
            message = "Bitte nur 1 Impfzertikat zeigen"
            yield(drawFrame(frame, [message], height, color_red))
            continue

        for barcode in barcodes:
            covid_cert_data = barcode.data.decode()

            # Strip the first characters to form valid Base45-encoded data
            try:
                b45data = covid_cert_data[4:]
            except:
                cv2.rectangle(frame, (x, y), (x + w, y + h), color_red, 10)
                yield(drawFrame(frame, ["Kein Impzertifikat"], height, color_red))
                continue

            # Decode the data
            try:
                zlibdata = base45.b45decode(b45data)
            except:
                (x, y, w, h) = barcode.rect
                cv2.rectangle(frame, (x, y), (x + w, y + h), color_red, 10)
                yield(drawFrame(frame, ["Kein Impzertifikat"], height, color_red))
                continue

            # Uncompress the data
            try:
                decompressed = zlib.decompress(zlibdata)
            except:
                (x, y, w, h) = barcode.rect
                cv2.rectangle(frame, (x, y), (x + w, y + h), color_red, 10)
                yield(drawFrame(frame, ["Kein Impzertifikat"], height, color_red))
                continue

            # decode COSE message (no signature verification done)
            try:
                cose_msg = CoseMessage.decode(decompressed)
            except:
                (x, y, w, h) = barcode.rect
                cv2.rectangle(frame, (x, y), (x + w, y + h), color_red, 10)
                yield(drawFrame(frame, ["Kein Impzertifikat"], height, color_red))
                continue

            # decode the CBOR encoded payload and print as json
            key_verified = False
            if KID in cose_msg.uhdr:
                log.info("COVID certificate signed with X.509 certificate.")
                log.info("X.509 in DER form has SHA-256 beginning with: {0}".format(
                    cose_msg.uhdr[KID].hex()))
                key = find_key(cose_msg.uhdr[KID],
                               DEFAULT_CERTIFICATE_DB_JSON)
                if key:
                    key_verified = verify_signature(cose_msg, key)
                else:
                    log.info("Skip verify as no key found from database")
            else:
                log.info("Certificate is not signed")

            cbor = cbor2.loads(cose_msg.payload)

            # Draw rectangle around barcode
            if key_verified and check_fully_vaccinated(cbor):
                rect_color = color_green
                text_color = color_green
            else:
                rect_color = color_red
                text_color = color_red

            (x, y, w, h) = barcode.rect
            cv2.rectangle(frame, (x, y), (x + w, y + h), rect_color, 10)

            # data to display
            cert_info = createMessage(cbor, key_verified)

        yield(drawFrame(frame, cert_info, height, text_color))


if __name__ == '__main__':
    videocapture()
