"""Confidence scoring: independent pieces of evidence add up to a 0-100 score."""
from __future__ import annotations

from ..models import Confidence, Leftover

WEIGHTS = {
    "install_dir": 90,              # is (or is inside) the recorded installation folder
    "uninstall_entry": 95,          # the program's own uninstall registry entry
    "product_code": 90,             # contains the MSI ProductCode
    "package_family": 95,           # Store package family folder
    "references_install_dir": 85,   # value/command/shortcut points into the install folder
    "exact_name": 65,               # name equals an identifying name (>= 6 chars)
    "exact_short_name": 45,         # name equals an identifying name of 4-5 chars
    "primary_name": 15,             # ...and it is the cleaned display name itself
    "publisher_parent": 20,         # located under a folder/key named after the publisher
    "publisher_folder": 45,         # is the publisher folder/key itself
    "only_app_content": 15,         # contains nothing but items attributed to the app
    "contains_app_exe": 25,         # contains one of the application's executables
    "exe_name": 30,                 # refers to one of the application's executables
    "target_missing": 20,           # the referenced file no longer exists
    "partial_name": 20,             # name merely contains an identifying name
    "author_publisher": 10,         # scheduled task author equals the publisher
    "shared_publisher": -30,        # other installed programs share this publisher
    "common_files": -15,            # under Common Files (often shared)
    "user_data": -25,               # under Documents: may hold the user's own files
    "target_elsewhere": -40,        # points to an existing file outside the install folder
    "foreign_key": -20,             # value lives under another vendor's key
    "msi_registration": -15,        # Windows Installer database entry: review before removing
}

HIGH = 80
MEDIUM = 50


def score(leftover: Leftover) -> int:
    total = sum(WEIGHTS.get(e.signal, 0) for e in leftover.evidence)
    return max(0, min(100, total))


def confidence_for(value: int) -> Confidence:
    if value >= HIGH:
        return Confidence.HIGH
    if value >= MEDIUM:
        return Confidence.MEDIUM
    return Confidence.LOW


def apply(leftover: Leftover) -> Leftover:
    leftover.score = score(leftover)
    leftover.confidence = confidence_for(leftover.score)
    # A partial name match alone can never be more than LOW, whatever else is added.
    strong = {e.signal for e in leftover.evidence} - {"partial_name", "author_publisher", "target_missing"}
    if not strong:
        leftover.confidence = Confidence.LOW
        leftover.score = min(leftover.score, MEDIUM - 1)
    return leftover
