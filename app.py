from flask import Flask, render_template, url_for, jsonify
from datetime import datetime
import re
import os
from os.path import join, dirname
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", name=os.getenv('TEST'))


@app.route("/user", methods=['GET'])
def user():
    return {"email": 'jow@bloggs.com', "age": 23}


if __name__ == "__main__":
    app.run(debug=True)
