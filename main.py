import sys
import signal
import threading
import server
from gunicorn.app.base import BaseApplication
import os
import dotenv


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


def run_gunicorn():
    workers = os.getenv('WORKERS', 1)
    threads = os.getenv('THREADS', 2)
    
    try:
        workers = int(workers)
    except (ValueError, TypeError):
        workers = 1
        
    try:
        threads = int(threads)
    except (ValueError, TypeError):
        threads = 2

    options = {
        'bind': '0.0.0.0:5000',
        'workers': workers,
        'threads': threads,
        'timeout': 120,
    }

    gunicorn_app = GunicornApp(server.app, options)
    print(f'Starting server with {workers} workers and {threads} threads', flush=True)
    gunicorn_app.run()


def signal_handler(sig, frame):
    print("Shutting down gracefully...", flush=True)
    
    # Shutdown the scheduler
    if server.scheduler.running:
        print("Stopping scheduler...", flush=True)
        server.scheduler.shutdown()
    
    # Shutdown the node check executors
    print("Shutting down thread pools...", flush=True)
    server.node_check_executor.shutdown(wait=False)
    server.sub_check_executor.shutdown(wait=False)
    
    sys.exit(0)


if __name__ == '__main__':
    dotenv.load_dotenv()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the scheduler from server.py
    # This ensures we use the robust APScheduler defined there instead of the custom loop
    print("Starting background scheduler...", flush=True)
    with server.app.app_context():
        server.start_scheduler()
        
        # Run an immediate check in a background thread so we don't block startup
        startup_thread = threading.Thread(target=server.scheduled_node_check)
        startup_thread.daemon = True
        startup_thread.start()
        
    try:
        # Run the Gunicorn server
        run_gunicorn()
    except KeyboardInterrupt:
        print("Shutting down server...", flush=True)
        signal_handler(signal.SIGINT, None)
