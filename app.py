from flask import Flask, render_template, url_for
from datetime import datetime
import re
import os
from os.path import join, dirname
from dotenv import load_dotenv

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", name=os.getenv('TESTss'))


if __name__ == "__main__":
    app.run(debug=True)
