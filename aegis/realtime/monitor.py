import os
import sys
import logging
from pathlib import Path
from typing import List, Optional, Callable

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from aegis.config import config
from aegis.realtime.event_handler import RealtimeEventHandler

logger = logging.getLogger("AegisRealtimeMonitor")

class AegisWatchdogHandler(FileSystemEventHandler):
    """Bridges watchdog filesystem events to the Aegis Realtime Event Handler."""

    def __init__(self, handler: RealtimeEventHandler):
        super().__init__()
        self.handler = handler

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self.handler.enqueue_file_event(event.src_path, "CREATED")

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.handler.enqueue_file_event(event.src_path, "MODIFIED")

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self.handler.enqueue_file_event(event.dest_path, "MOVED")


class RealtimeMonitor:
    """Manages active filesystem observer hooks across sensitive endpoint directories."""

    def __init__(self, event_handler: Optional[RealtimeEventHandler] = None):
        self.event_handler = event_handler or RealtimeEventHandler()
        self.observer: Optional[Observer] = None
        self.monitored_paths: List[str] = []
        self.is_active = False

    def start(self, custom_paths: Optional[List[str]] = None):
        """Starts real-time filesystem observation."""
        if self.is_active:
            return

        self.event_handler.start()
        self.observer = Observer()
        watch_handler = AegisWatchdogHandler(self.event_handler)

        paths = custom_paths or config.get("monitored_paths", [])
        self.monitored_paths = []

        for p in paths:
            if not p:
                continue
            resolved = os.path.expandvars(p)
            if os.path.exists(resolved):
                try:
                    self.observer.schedule(watch_handler, path=resolved, recursive=True)
                    self.monitored_paths.append(resolved)
                    logger.info(f"Attached real-time protection hook to: {resolved}")
                except Exception as e:
                    logger.warning(f"Could not hook directory {resolved}: {e}")

        if self.monitored_paths:
            self.observer.start()
            self.is_active = True
            logger.info("Real-time filesystem protection is ACTIVE.")
        else:
            logger.warning("No valid directories found to monitor for real-time protection.")

    def stop(self):
        """Stops the real-time protection observer."""
        if not self.is_active:
            return

        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3.0)
            self.observer = None

        self.event_handler.stop()
        self.is_active = False
        logger.info("Real-time filesystem protection STOPPED.")

    def get_status(self) -> dict:
        return {
            "active": self.is_active,
            "monitored_paths": self.monitored_paths,
            "queue_size": self.event_handler.event_queue.qsize() if self.event_handler else 0,
        }
