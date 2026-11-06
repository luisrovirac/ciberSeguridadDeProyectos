import pickle
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    # Intentionally insecure for testing: command injection
    return subprocess.check_output("ping -c 1 " + request.args["host"], shell=True)


@app.route("/load", methods=["POST"])
def load():
    data = yaml.load(request.data)  # Intentionally insecure: unsafe YAML load
    obj = pickle.loads(request.data)  # Intentionally insecure: deserialization
    return str(data) + str(obj)


if __name__ == "__main__":
    app.run(debug=True)
