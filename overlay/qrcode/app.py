from flask import Flask, render_template, Response
from vacdec import videocapture
import cv2

app = Flask(__name__)

cap = cv2.VideoCapture(0)

@app.route("/")
def hello_world():
    return render_template("index.html")

@app.route("/stream")
def video_stream():
    return Response(videocapture(cap), mimetype="multipart/x-mixed-replace; boundary=frame")

if __name__ == '__main__':
    app.run(host='10.1.0.1', port=8080)