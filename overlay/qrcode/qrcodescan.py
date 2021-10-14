import cv2
from pyzbar import pyzbar
import base45
import zlib
import cbor2

def videocapture():
    vid = cv2.VideoCapture(0)

    cert_info = ["Suche QR-Code..."]

    while True:
        ret, frame = vid.read()   
        # width and height of the frame
        width = int(vid.get(3))
        height = int(vid.get(4))

        barcodes = pyzbar.decode(frame)

        if not barcodes:
            cert_info = ["Suche QR-Code..."]

        for barcode in barcodes:
            # Draw rectangle around barcode
            (x, y, w, h) = barcode.rect
            cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 5)
            
            # Decode data and print to console
            cert = barcode.data.decode()
            b45data = cert.replace("HC1:", "")
            zlibdata = base45.b45decode(b45data)
            cbordata = zlib.decompress(zlibdata)
            decoded = cbor2.loads(cbordata)
            # python dict
            payload = cbor2.loads(decoded.value[2])
            
            cert_info = [
                payload[-260][1]['nam']['fn'] + " " + payload[-260][1]['nam']['gn'],
                str(payload[-260][1]['v'][0]['dn']) + " von " + str(payload[-260][1]['v'][0]['sd']) + " Impfungen erhalten"
            ]

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