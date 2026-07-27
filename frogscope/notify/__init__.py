"""Notification hooks.

Split deliberately in two:

* `alerts.py` builds the alert from the database. Pure, no network, fully
  testable — which is what lets the interesting logic (what is worth alerting
  on, and what has already been alerted) be tested without a webhook.
* `sinks.py` delivers it. The only part that opens a socket, and it is reached
  only when both `notify.yaml:enabled` and `--send` say so.
"""

from .alerts import Alert, AlertItem, build_alert, load_notify_config
from .sinks import deliver, record

__all__ = ["Alert", "AlertItem", "build_alert", "load_notify_config",
           "deliver", "record"]
