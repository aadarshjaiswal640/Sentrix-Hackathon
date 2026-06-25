# service.py
import sys
import time
import threading
import servicemanager
import win32event
import win32service
import win32serviceutil

from main import boot
from logger import log


class SentrixService(win32serviceutil.ServiceFramework):
    _svc_name_         = "SentrixAgent"
    _svc_display_name_ = "Sentrix SOC Agent"
    _svc_description_  = "Sentrix endpoint monitoring and SOC agent"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running    = True

    def SvcStop(self):
        log("Sentrix Service stopping...", "INFO")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        log("Sentrix Service starting...", "INFO")

        # Run boot() in background thread
        thread = threading.Thread(target=boot, daemon=True)
        thread.start()

        # Keep service alive until stop signal
        while self.running:
            rc = win32event.WaitForSingleObject(self.stop_event, 5000)
            if rc == win32event.WAIT_OBJECT_0:
                break

        log("Sentrix Service stopped.", "INFO")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SentrixService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SentrixService)