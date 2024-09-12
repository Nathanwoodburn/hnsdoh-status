import time
import signal
import threading
from flask import Flask
from server import app
import server
from gunicorn.app.base import BaseApplication
import os
import dotenv
import concurrent.futures
import schedule


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


def check():
    print('Checking nodes...', flush=True)
    server.check_nodes()


def run_scheduler(stop_event):
    schedule.every(1).minutes.do(check)
    while not stop_event.is_set():
        schedule.run_pending()
        time.sleep(1)


def run_gunicorn():
    workers = os.getenv('WORKERS', 1)
    threads = os.getenv('THREADS', 2)
    workers = int(workers)
    threads = int(threads)

    options = {
        'bind': '0.0.0.0:5000',
        'workers': workers,
        'threads': threads,
    }

    gunicorn_app = GunicornApp(server.app, options)
    print(f'Starting server with {workers} workers and {threads} threads', flush=True)
    gunicorn_app.run()


def signal_handler(sig, frame):
    print("Shutting down gracefully...", flush=True)
    stop_event.set()


if __name__ == '__main__':
    dotenv.load_dotenv()
    
    stop_event = threading.Event()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Start the scheduler
        scheduler_future = executor.submit(run_scheduler, stop_event)
        
        try:
            # Run the Gunicorn server
            run_gunicorn()
        except KeyboardInterrupt:
            print("Shutting down server...", flush=True)
        finally:
            stop_event.set()
            scheduler_future.cancel()
            try:
                scheduler_future.result(timeout=5)
            except concurrent.futures.CancelledError:
                print("Scheduler stopped.")
            except Exception as e:
                print(f"Scheduler did not stop cleanly: {e}")
