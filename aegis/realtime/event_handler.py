import os
import time
import queue
import logging
import threading
from typing import Optional, Callable, Dict, Any, Set
from aegis.config import config
from aegis.engine.scanner import AntivirusScanner, ScanResult
from aegis.quarantine.manager import QuarantineManager

logger = logging.getLogger("AegisRealtimeEvents")

class RealtimeEventHandler:
    """Processes filesystem change events, debounces duplicate bursts, and executes immediate scans."""

    def __init__(
        self,
        scanner: Optional[AntivirusScanner] = None,
        quarantine_mgr: Optional[QuarantineManager] = None,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.scanner = scanner or AntivirusScanner()
        self.quarantine_mgr = quarantine_mgr or QuarantineManager()
        self.alert_callback = alert_callback

        self.event_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.recent_scans: Dict[str, float] = {}  # filepath -> last_scanned_timestamp (debounce)
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None

    def start(self):
        self.running = True
        self.worker_thread = threading.Thread(target=self._process_queue, name="Aegis-Realtime-Worker", daemon=True)
        self.worker_thread.start()
        logger.info("Real-time event processing worker started.")

    def stop(self):
        self.running = False
        if self.worker_thread and self.worker_thread.is_alive():
            self.event_queue.put(None)  # Sentinel to unblock
            self.worker_thread.join(timeout=2.0)
        logger.info("Real-time event processing worker stopped.")

    def enqueue_file_event(self, filepath: str, event_type: str = "MODIFIED"):
        """Pushes an incoming file creation or modification event to the worker queue."""
        if not self.running:
            return

        norm_path = os.path.normpath(filepath)

        # Skip excluded paths (e.g. quarantine vault itself, logs)
        excluded = [os.path.normpath(p).lower() for p in config.get("excluded_paths", [])]
        if any(norm_path.lower().startswith(ex) for ex in excluded):
            return

        # Skip non-executable/harmless log files if configured
        ext = os.path.splitext(norm_path)[1].lower()
        if ext in config.get("excluded_extensions", []):
            return

        # Debounce: If scanned within the last 1.5 seconds, ignore duplicate flush
        now = time.time()
        if norm_path in self.recent_scans:
            if now - self.recent_scans[norm_path] < 1.5:
                return

        self.recent_scans[norm_path] = now
        try:
            self.event_queue.put_nowait((norm_path, event_type, now))
        except queue.Full:
            logger.warning("Real-time event queue full; dropping event for %s", norm_path)

    def _process_queue(self):
        while self.running:
            try:
                item = self.event_queue.get(timeout=0.5)
                if item is None:
                    break

                filepath, event_type, timestamp = item
                self._handle_file(filepath, event_type)
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in realtime worker: {e}")

    def _handle_file(self, filepath: str, event_type: str):
        if not os.path.exists(filepath):
            return

        # Scan the file
        result: ScanResult = self.scanner.scan_file(filepath)

        if result.is_infected:
            logger.warning(
                f"[REALTIME ALERT] Threat detected in {filepath}! "
                f"Threat: {result.threat_name} ({result.severity}, confidence: {result.confidence}%)"
            )

            # Auto-quarantine
            q_res = self.quarantine_mgr.quarantine_file(
                filepath=filepath,
                threat_name=result.threat_name or "Malware.Generic",
                detection_method=result.detection_method or "REALTIME",
                severity=result.severity,
                confidence=result.confidence,
                reasons=result.reasons,
                operator="AegisShield-RealtimeGuard",
            )

            event_payload = {
                "event_type": "REALTIME_THREAT_INTERCEPTED",
                "filepath": filepath,
                "threat_name": result.threat_name,
                "severity": result.severity,
                "confidence": result.confidence,
                "detection_method": result.detection_method,
                "reasons": result.reasons,
                "sha256": result.sha256,
                "quarantined": q_res.get("success", False),
                "quarantine_id": q_res.get("quarantine_id"),
                "timestamp": time.time(),
            }

            if self.alert_callback:
                try:
                    self.alert_callback(event_payload)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")
