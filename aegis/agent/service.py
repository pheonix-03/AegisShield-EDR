import os
import sys
import time
import logging
import threading
from typing import Optional

from aegis.config import config, LOG_FILE
from aegis.engine.scanner import AntivirusScanner
from aegis.quarantine.manager import QuarantineManager
from aegis.realtime.monitor import RealtimeMonitor
from aegis.realtime.event_handler import RealtimeEventHandler
from aegis.ransomware.tripwire import CanaryTripwire
from aegis.ransomware.process_watcher import RansomwareBehaviorWatcher
from aegis.usb.detector import USBSecurityManager
from aegis.network.conn_monitor import NetworkConnectionMonitor
from aegis.agent.client import EndpointAgentClient

logger = logging.getLogger("AegisService")

class AegisShieldCoreService:
    """Orchestrates all local defensive subsystems and background agent loops."""

    def __init__(self):
        self.is_running = False
        self.scanner = AntivirusScanner()
        self.quarantine_mgr = QuarantineManager()

        # Connect alerts to agent telemetry client
        self.agent_client = EndpointAgentClient(
            scanner=self.scanner,
            quarantine_mgr=self.quarantine_mgr,
        )

        def _on_threat_alert(alert: dict):
            logger.warning(f"Core Threat Alert: {alert}")
            self.agent_client.report_incident(
                threat_name=alert.get("threat_name", "DetectedThreat"),
                threat_type="REALTIME_INTERCEPT",
                severity=alert.get("severity", "HIGH"),
                confidence=alert.get("confidence", 90),
                filepath=alert.get("filepath"),
                sha256=alert.get("sha256"),
                detection_method=alert.get("detection_method", "REALTIME"),
                remediation_status="QUARANTINED" if alert.get("quarantined") else "PENDING",
                details=json.dumps(alert.get("reasons", [])),
            )

        self.event_handler = RealtimeEventHandler(
            scanner=self.scanner,
            quarantine_mgr=self.quarantine_mgr,
            alert_callback=_on_threat_alert,
        )
        self.realtime_monitor = RealtimeMonitor(self.event_handler)
        self.agent_client.realtime_monitor = self.realtime_monitor

        # Ransomware Tripwire
        def _on_tripwire(violation: dict):
            logger.critical(f"Ransomware Tripwire Tripped: {violation}")
            self.agent_client.report_incident(
                threat_name="Ransomware.CanaryTripwire.Tripped",
                threat_type="RANSOMWARE",
                severity="CRITICAL",
                confidence=98,
                filepath=violation.get("path"),
                remediation_status="CANARY_TRIPWIRE_TRIGGERED",
                details=violation.get("reason"),
            )

        self.tripwire = CanaryTripwire(on_tripwire_tripped=_on_tripwire)
        self.ransomware_watcher = RansomwareBehaviorWatcher()

        # USB Manager
        self.usb_manager = USBSecurityManager(scanner=self.scanner)

        # Network Monitor
        self.conn_monitor = NetworkConnectionMonitor(auto_block=False)

        # Background maintenance threads
        self.threads = []

    def start(self):
        """Starts all defensive subsystems."""
        if self.is_running:
            return
        self.is_running = True
        logger.info("Initializing AegisShield Endpoint Protection Service...")

        # 1. Real-time filesystem observer
        if config.get("realtime_protection_enabled", True):
            self.realtime_monitor.start()

        # 2. Canary honey-files check
        self.tripwire.setup_canaries()

        # 3. Agent communication loop with server
        self.agent_client.start_loop()

        # 4. Background auxiliary loop (USB polling, canary audits, network scans)
        t_aux = threading.Thread(target=self._auxiliary_loop, name="Aegis-Aux-Loop", daemon=True)
        t_aux.start()
        self.threads.append(t_aux)

        logger.info("All AegisShield defensive engines are ACTIVE and protecting host.")

    def stop(self):
        """Cleanly shuts down all engines."""
        if not self.is_running:
            return
        self.is_running = False
        logger.info("Shutting down AegisShield Endpoint Service...")

        self.realtime_monitor.stop()
        self.agent_client.stop_loop()
        logger.info("AegisShield Endpoint Service safely halted.")

    def _auxiliary_loop(self):
        canary_check_counter = 0
        while self.is_running:
            try:
                # Poll USB insertion
                if config.get("usb_protection_enabled", True):
                    self.usb_manager.poll_usb_events()

                # Audit canary traps every ~15 seconds
                canary_check_counter += 1
                if canary_check_counter >= 3:
                    canary_check_counter = 0
                    self.tripwire.verify_canaries()

                # Audit outbound network connections
                if config.get("web_protection_enabled", True):
                    self.conn_monitor.audit_active_connections()

            except Exception as e:
                logger.debug(f"Auxiliary loop error: {e}")

            time.sleep(5.0)

# Optional Windows Service Framework integration if pywin32 service tools are invoked
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager

    class AegisWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "AegisShieldEDR"
        _svc_display_name_ = "AegisShield Endpoint Detection & Response Service"
        _svc_description_ = "Real-time antivirus, ransomware tripwire, and endpoint management service."

        def __init__(self, args):
            super().__init__(args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.service = AegisShieldCoreService()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.service.stop()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "")
            )
            self.service.start()
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

except ImportError:
    AegisWindowsService = None


def run_standalone():
    """Runs the service in interactive standalone console mode."""
    svc = AegisShieldCoreService()
    svc.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        svc.stop()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        run_standalone()
    elif AegisWindowsService and len(sys.argv) > 1:
        win32serviceutil.HandleCommandLine(AegisWindowsService)
    else:
        run_standalone()
