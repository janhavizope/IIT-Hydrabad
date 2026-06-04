"""Shared constants for assessment modules."""

from __future__ import annotations

import re

WEIGHT_STATIC = 0.40
WEIGHT_DYNAMIC = 0.50
WEIGHT_IOC = 0.10

SCORE_CAP_WITHOUT_CHAIN = 55
MALICIOUS_SCORE_THRESHOLD = 76
SAFE_SCORE_THRESHOLD = 40
SUSPICIOUS_SCORE_MAX = 75
MALICIOUS_CONFIDENCE_DOWNGRADE_CAP = 74
SMALL_DATASET_EVENT_THRESHOLD = 10

CHAIN_STRENGTH_THRESHOLD = 0.75
HIGH_SYSTEM_NOISE_RATIO = 0.6
CONFIDENCE_NOISE_PENALTY_RATIO = 0.5
HIGH_IOC_VOLUME_THRESHOLD = 50

IOC_WEIGHT_SUSPICIOUS = 0.6
IOC_WEIGHT_MALICIOUS = 1.0
IOC_SCORE_CAP = 40.0

KNOWN_EVENT_TYPES = frozenset({"activity", "network", "permission", "error", "system"})

# Fully excluded from dynamic scoring (never downweighted — dropped at filter).
SYSTEM_SOURCES = (
    "activitymanager",
    "system_server",
    "com.google.android.gms",
    "com.android.inputmethod",
    "com.google.android.tts",
    "binder",
    "android.os",
    "logcat",
    "zygote",
    "surfaceflinger",
    "systemui",
    "lowmemorykiller",
)

# Logcat / system tag patterns (substring match on tag or message).
LOGCAT_SYSTEM_MARKERS = (
    "system_server",
    "am_proc",
    "am_create",
    "am_destroy",
    "binder:",
    "libc",
    "dalvik",
    "art:",
)

DANGEROUS_PERMISSION_NAMES = frozenset(
    {
        "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "WRITE_EXTERNAL_STORAGE",
        "READ_CONTACTS", "WRITE_CONTACTS", "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION", "RECORD_AUDIO", "CAMERA", "READ_PHONE_STATE",
        "READ_CALENDAR", "WRITE_CALENDAR", "INSTALL_PACKAGES", "GET_ACCOUNTS",
    }
)

DANGEROUS_API_KEYWORDS = (
    "runtime.exec", "processbuilder", "dexclassloader", "pathclassloader",
    "smsmanager", "telephonymanager", "locationmanager",
)

SENSITIVE_ACTION_MARKERS = (
    "read_sms", "send_sms", "sms", "contacts", "content://contacts",
    "location", "getlastknownlocation", "fileoutputstream", "write",
    "delete", "chmod", "runtime.exec", "processbuilder", "clipboard",
    "getdeviceid", "getsubscriberid",
)

DATA_MOVEMENT_MARKERS = (
    "upload", "post ", "put ", "exfil", "transmit", "bytes sent", "send ",
    "http", "https",
)

TRUSTED_DOMAIN_PREFIXES = (
    "com.android.", "android.", "com.google.", "google.", "gms.",
    "play.googleapis.", "firebase.", "googleapis.",
)

TRUSTED_PACKAGE_PREFIXES = (
    "com.android.",
    "android.",
    "com.google.android.gms",
    "com.google.android.gsf",
)

# System events kept for IOC extraction only (never scored).
SYSTEM_ABUSE_MARKERS = (
    "packageinstaller",
    "pm install",
    "pm grant",
    "grant permission",
    "revoke permission",
    "install package",
    "delete package",
    "securityexception",
    "permission denial",
    "access denied",
    "appops",
    "devicepolicy",
)

NOISE_SOURCE_MARKERS = (
    "activitymanager",
    "activity manager",
    "am ",
    "binder:",
    "binder ",
    "system_server",
    "system server",
    "systemui",
    "com.android.inputmethod",
    "com.google.android.inputmethod",
    "com.google.android.tts",
    "texttospeech",
    "google play",
    "play services",
    "boot ",
    "emulator",
    "goldfish",
    "dalvik",
    "art:",
    "gralloc",
    "surfaceflinger",
    "lowmemorykiller",
)

MALICIOUS_IOC_KEYWORDS = (
    "phish", "steal", "exfil", "c2", "botnet", "spy", "keylog",
)

OBFUSCATION_MARKERS = ("base64", "xor", "encrypt", "decode", "cipher", "obfus", "\\x")

SECRET_PATTERNS = (
    re.compile(r"\b(api[_-]?key|secret|token|password|credential|bearer)\s*[:=]", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.", re.I),
)

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))\b",
)
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
)

PRIVATE_IP_PREFIXES = ("10.", "172.", "192.168.", "127.", "0.0.0.0")

NO_VALID_ATTACK_CHAIN = "No valid attack chain detected"
