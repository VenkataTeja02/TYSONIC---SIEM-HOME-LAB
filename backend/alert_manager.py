"""
SIEM Alert Manager — Orchestrates detection → alert generation → storage → correlation → reporting → notification
"""

import json
import threading
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any
from alert_engine import Alert, AlertStorage, TelegramNotifier, Severity, SEVERITY_SCORE
from report_generator import ReportGenerator
from siem_logger import get_logger

logger = get_logger(__name__)

_correlation_engine = None

CONFIG_PATH = Path("./siem_data/config.json")

DEFAULT_CONFIG = {
    "telegram": {
        "token":   "",
        "chat_id": "",
        "enabled": False,
    },
    "thresholds": {
        "report_on_severity":    ["High", "Critical"],
        "telegram_on_severity":  ["High", "Critical"],
    },
}


class AlertManager:
    def __init__(self, data_dir: str = "./siem_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.storage  = AlertStorage(str(data_dir))
        self.reporter = ReportGenerator(str(self.data_dir / "reports"))
        self.config   = self._load_config()
        self._listeners: List[Callable[[Alert], None]] = []

    # ─────────── Config ────────────────────────

    def save_config(self, config):
        self.config = config
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        logger.info("Config saved.")

    def _load_config(self) -> Dict:
        import copy
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH) as f:
                    saved = json.load(f)
                cfg = copy.deepcopy(DEFAULT_CONFIG)
                for k in cfg:
                    if k not in saved:
                        continue
                    if isinstance(cfg[k], dict) and isinstance(saved[k], dict):
                        for sk in cfg[k]:
                            if sk in saved[k]:
                                cfg[k][sk] = saved[k][sk]
                    else:
                        cfg[k] = saved[k]
                return cfg
            except Exception:
                pass
        return copy.deepcopy(DEFAULT_CONFIG)

    def update_telegram_config(self, token: str, chat_id: str, enabled: bool = True):
        self.config["telegram"].update({"token": token, "chat_id": chat_id, "enabled": enabled})
        self.save_config(self.config)


    def set_correlation_engine(self, engine):
        """Inject the correlation engine after initialisation (avoids circular import)."""
        global _correlation_engine
        _correlation_engine = engine

    # ─────────── Alert Creation ─────────────────

    def create_alert(
        self,
        alert_type:   str,
        severity:     Severity,
        source_ip:    str,
        dest_ip:      str,
        description:  str,
        log_evidence: str,
        tags:         List[str] = None,
    ) -> Alert:
        return Alert(
            alert_type   = alert_type,
            severity     = severity,
            source_ip    = source_ip,
            dest_ip      = dest_ip,
            description  = description,
            log_evidence = log_evidence,
            tags         = tags or [],
        )

    # ─────────── Processing Pipeline ────────────

    def process(self, alert: Alert) -> Dict[str, Any]:
        """
        Full pipeline:
          1. Save alert to storage
          2. Notify real-time listeners (dashboard)
          3. Generate reports if severity threshold met
          4. Send Telegram notification
        Returns dict with paths to generated artifacts.
        """
        result = {
            "alert_id":    alert.alert_id,
            "html_report": None,
            "telegram_sent": False,
        }

        # 1. Store
        self.storage.save(alert)
        logger.info("Alert stored: %s [%s] %s", alert.alert_id[:8], alert.severity.value, alert.alert_type)

        # 1b. Audit log
        self.storage.audit_log("alert_created", "system", f"{alert.alert_type} from {alert.source_ip}")

        # 1c. Run correlation engine against latest alerts (non-blocking)
        if _correlation_engine is not None:
            threading.Thread(
                target=lambda: _correlation_engine.evaluate(self.storage.get_all()),
                daemon=True
            ).start()

        # 2. Real-time listeners
        for fn in self._listeners:
            try:
                fn(alert)
            except Exception as e:
                logger.error("Alert listener error: %s", e, exc_info=True)

        sev       = alert.severity.value if hasattr(alert.severity, "value") else alert.severity
        report_on = self.config["thresholds"]["report_on_severity"]
        tg_on     = self.config["thresholds"]["telegram_on_severity"]

        # 3. Generate HTML report
        if sev in report_on:
            result["html_report"] = self.reporter.generate_html(alert)

        # 4. Telegram notification
        tg = self.config.get("telegram", {})
        if sev in tg_on and tg.get("enabled") and tg.get("token") and tg.get("chat_id"):
            notifier = TelegramNotifier(
                telegram_token=tg["token"],
                telegram_chat=tg["chat_id"],
            )
            # Fire in background so it never blocks the pipeline
            def _send_tg(n=notifier, a=alert, r=result):
                ok = n.send(a)
                r["telegram_sent"] = ok
            threading.Thread(target=_send_tg, daemon=True).start()
        else:
            result["telegram_sent"] = False

        return result

    # ─────────── Real-time Listener API ─────────

    def add_listener(self, fn: Callable[[Alert], None]):
        """Register a callback that receives every new Alert in real-time."""
        self._listeners.append(fn)

    def remove_listener(self, fn):
        self._listeners = [x for x in self._listeners if x is not fn]

    # ─────────── Query ────────────────────────

    def get_incidents(self) -> List[Dict]:
        return self.storage.get_all()

    def get_stats(self) -> Dict:
        return self.storage.stats()

    def acknowledge(self, alert_id: str, user: str = "system"):
        self.storage.update_status(alert_id, "acknowledged")
        self.storage.audit_log("alert_acknowledged", user, alert_id)

    def resolve(self, alert_id: str, user: str = "system"):
        self.storage.update_status(alert_id, "resolved")
        self.storage.audit_log("alert_resolved", user, alert_id)

    def get_config(self) -> Dict:
        return json.loads(json.dumps(self.config))
