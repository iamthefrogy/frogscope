"""Running the external scanners.

Separated from everything else because it is the only code that generates traffic
to infrastructure Frogscope does not own. Analysis never does: this module's
output is a CSV, and from there a scan and an uploaded file follow exactly the
same path.
"""

from .options import OptionError, ScanOptions, catalogue, parse
from .runner import Cancelled, EmptyResult, ScanError, ScanRun
from .tools import inventory, missing

__all__ = ["OptionError", "ScanOptions", "catalogue", "parse",
           "Cancelled", "EmptyResult", "ScanError", "ScanRun", "inventory", "missing"]
