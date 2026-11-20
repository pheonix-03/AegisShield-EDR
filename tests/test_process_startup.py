import pytest
from aegis.process_security.process_inspector import ProcessInspector
from aegis.process_security.startup_inspector import StartupInspector

def test_list_running_processes():
    procs = ProcessInspector.list_running_processes(check_signatures=False)
    assert len(procs) > 0
    # Current python process should be listed
    pids = [p["pid"] for p in procs]
    import os
    assert os.getpid() in pids

def test_startup_persistence_audit():
    res = StartupInspector.audit_all_persistence()
    assert "total_persistence_entries" in res
    assert "registry_run_entries" in res
    assert "startup_folder_entries" in res
    assert isinstance(res["suspicious_count"], int)
