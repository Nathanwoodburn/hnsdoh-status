import time
from flask import Flask
from server import app
import server
from gunicorn.app.base import BaseApplication
import os
import dotenv
import sys
import json


class GunicornApp(BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        for key, value in self.options.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

if __name__ == '__main__':
    workers = os.getenv('WORKERS')
    threads = os.getenv('THREADS')
    if workers is None:
        workers = 1
    if threads is None:
        threads = 2
    workers = int(workers)
    threads = int(threads)
    options = {
        'bind': '0.0.0.0:5000',
        'workers': workers,
        'threads': threads,
    }
    gunicorn_app = GunicornApp(app, options)
    print('Starting server with ' + str(workers) + ' workers and ' + str(threads) + ' threads', flush=True)
    gunicorn_app.run()
