from flask import Flask, render_template, Response
from qrcodescan import videocapture

app = Flask(__name__)

@app.route("/")
def hello_world():
    return render_template("index.html")

@app.route("/stream")
def video_stream():
    return Response(videocapture(), mimetype="multipart/x-mixed-replace; boundary=frame")

