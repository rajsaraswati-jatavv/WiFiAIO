"""802.11 reason codes and status codes.

Defines IEEE 802.11 reason codes (1-99) and status codes (0-80) used
in management frames for disassociation, deauthentication, and
association response frames.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# ── 802.11 Reason Codes (1-99) ──────────────────────────────────────────
REASON_CODES: Dict[int, Dict] = {
    1:  {"name": "UNSPECIFIED",               "description": "Unspecified reason",                                    "category": "general"},
    2:  {"name": "PREV_AUTH_NOT_VALID",        "description": "Previous authentication no longer valid",               "category": "authentication"},
    3:  {"name": "DEAUTH_LEAVING",             "description": "Deauthenticated because sending STA is leaving BSS",     "category": "general"},
    4:  {"name": "DISASSOC_DUE_TO_INACTIVITY", "description": "Disassociated due to inactivity",                       "category": "timeout"},
    5:  {"name": "DISASSOC_AP_BUSY",           "description": "Disassociated because AP is unable to handle all STAs", "category": "capacity"},
    6:  {"name": "CLASS2_FRAME_FROM_NONAUTH",  "description": "Class 2 frame received from non-authenticated STA",     "category": "authentication"},
    7:  {"name": "CLASS3_FRAME_FROM_NONASSOC", "description": "Class 3 frame received from non-associated STA",         "category": "association"},
    8:  {"name": "DISASSOC_STA_HAS_LEFT",      "description": "Disassociated because STA has left BSS",                "category": "general"},
    9:  {"name": "STA_REQ_ASSOC_NO_AUTH",      "description": "STA requesting association not authenticated",          "category": "authentication"},
    10: {"name": "DISASSOC_BAD_POWER",         "description": "Disassociated due to power capability unacceptable",     "category": "capability"},
    11: {"name": "DISASSOC_BAD_CHANNELS",      "description": "Disassociated due to supported channels unacceptable",   "category": "capability"},
    12: {"name": "INVALID_ELEMENT",            "description": "Invalid element in 802.11 frame",                       "category": "protocol"},
    13: {"name": "MIC_FAILURE",                "description": "MIC failure in received frame (TKIP/CCMP)",             "category": "security"},
    14: {"name": "FOURWAY_TIMEOUT",            "description": "4-Way Handshake timeout",                               "category": "security"},
    15: {"name": "GK_TIMEOUT",                 "description": "Group Key Handshake timeout",                           "category": "security"},
    16: {"name": "FOURWAY_DIFF_INFO",          "description": "4-Way Handshake information differs from prior",        "category": "security"},
    17: {"name": "GROUP_CIPHER_INVALID",       "description": "Invalid group cipher",                                  "category": "security"},
    18: {"name": "PAIRWISE_CIPHER_INVALID",    "description": "Invalid pairwise cipher",                               "category": "security"},
    19: {"name": "AKMP_INVALID",               "description": "Invalid AKMP",                                          "category": "security"},
    20: {"name": "UNSUPPORTED_RSN_VERSION",    "description": "Unsupported RSN information element version",           "category": "security"},
    21: {"name": "INVALID_RSN_CAPABILITIES",   "description": "Invalid RSN information element capabilities",          "category": "security"},
    22: {"name": "FOURWAY_POLICY",             "description": "802.1X authentication failed (4-way policy)",           "category": "security"},
    23: {"name": "CIPHER_REJECTED",            "description": "Cipher suite rejected due to security policy",          "category": "security"},
    24: {"name": "TS_DELAY_THRESHOLD",         "description": "TS delay threshold violated",                           "category": "qos"},
    25: {"name": "DIRECTLINK_FORBIDDEN",       "description": "Direct link not allowed in BSS",                        "category": "qos"},
    26: {"name": "STA_NOT_IN_BSS",             "description": "Destination STA not within same BSS",                   "category": "association"},
    27: {"name": "STA_NOT_IN_PEER_BSS",        "description": "Destination STA not within same peer BSS",              "category": "association"},
    28: {"name": "STA_NOT_IN_PEER",            "description": "STA not a member of the peer group",                    "category": "association"},
    29: {"name": "QBSS_REQUIRED",              "description": "Request rejected - QBSS required",                      "category": "qos"},
    30: {"name": "UNSPECIFIED_QOS",            "description": "Unspecified QoS-related reason",                        "category": "qos"},
    31: {"name": "INSUFFICIENT_BANDWIDTH",     "description": "Disassociated due to insufficient bandwidth",            "category": "qos"},
    32: {"name": "POOR_CHANNEL_CONDITIONS",    "description": "Disassociated due to poor channel conditions",           "category": "qos"},
    33: {"name": "QOS_STA_LEAVING",            "description": "QoS STA leaving the BSS",                               "category": "qos"},
    34: {"name": "REJECTED_FOR_DELAY",         "description": "QoS request rejected due to delay constraint",          "category": "qos"},
    35: {"name": "REJECTED_FOR_SLO",           "description": "QoS request rejected - SLO constraint",                 "category": "qos"},
    36: {"name": "REJECTED_FOR_SSB",           "description": "QoS request rejected - SSB constraint",                 "category": "qos"},
    37: {"name": "TSPEC_REJECTED_PARAMS",      "description": "TSPEC parameters not accepted",                         "category": "qos"},
    38: {"name": "INVALID_TSID",               "description": "Invalid TSID in DELTS request",                         "category": "qos"},
    39: {"name": "TRAFFIC_NOT_SCHEDULED",      "description": "Traffic not scheduled for DELBA",                       "category": "qos"},
    40: {"name": "TCLAS_PROCESSING_ERROR",     "description": "TCLAS processing error",                                "category": "qos"},
    41: {"name": "SCHEDULE_CONFLICT",          "description": "TS schedule conflict",                                  "category": "qos"},
    42: {"name": "UNSPECIFIED_MFP",            "description": "Unspecified reason with MFP",                           "category": "security"},
    43: {"name": "MFP_POLICY_VIOLATION",       "description": "Management frame protection policy violation",          "category": "security"},
    44: {"name": "UNSPECIFIED_FILS",           "description": "Unspecified FILS reason",                               "category": "authentication"},
    45: {"name": "INSUFFICIENT_FILS_AUTH",     "description": "Insufficient FILS authentication data",                 "category": "authentication"},
    46: {"name": "FILS_AUTH_SERVER_UNREACHABLE","description": "FILS authentication server unreachable",              "category": "authentication"},
    47: {"name": "FILS_AUTH_SERVER_FAILURE",   "description": "FILS authentication server failure",                    "category": "authentication"},
    48: {"name": "INVALID_PMKID",             "description": "Invalid PMKID in (Re)Association Request",              "category": "security"},
    49: {"name": "INVALID_MDE",               "description": "Invalid MDE in (Re)Association Request",                "category": "security"},
    50: {"name": "INVALID_FTE",               "description": "Invalid FTE in (Re)Association Request",                "category": "security"},
    51: {"name": "INVALID_PMK",               "description": "Invalid PMK for mesh peering",                          "category": "security"},
    52: {"name": "INVALID_MESH_CONFIG",        "description": "Invalid mesh configuration",                            "category": "mesh"},
    53: {"name": "INVALID_MESH_GK",            "description": "Invalid mesh group key",                                "category": "security"},
    54: {"name": "INVALID_MESH_SAE",           "description": "Invalid mesh SAE authentication",                       "category": "security"},
    55: {"name": "MESH_PEER_REJECTED",         "description": "Mesh peering rejected",                                 "category": "mesh"},
    56: {"name": "MESH_PEER_CANCELED",         "description": "Mesh peering canceled",                                 "category": "mesh"},
    57: {"name": "MESH_MAX_PEERS",             "description": "Maximum number of mesh peers reached",                   "category": "mesh"},
    58: {"name": "MESH_CONFIG_VIOLATION",      "description": "Mesh configuration policy violation",                   "category": "mesh"},
    59: {"name": "MESH_CLOSE_RCVD",            "description": "Mesh close received",                                   "category": "mesh"},
    60: {"name": "MESH_MAX_RETRIES",           "description": "Mesh maximum retries exceeded",                          "category": "mesh"},
    61: {"name": "MESH_CONFIRM_TIMEOUT",       "description": "Mesh confirm timeout",                                  "category": "mesh"},
    62: {"name": "MESH_INVALID_GK",            "description": "Mesh invalid GTK",                                      "category": "security"},
    63: {"name": "MESH_INCONSISTENT_PARAMS",   "description": "Mesh inconsistent parameters",                          "category": "mesh"},
    64: {"name": "MESH_INVALID_SECURITY",      "description": "Mesh invalid security parameters",                      "category": "security"},
    65: {"name": "MESH_INVALID_CAPS",          "description": "Mesh invalid capabilities",                             "category": "mesh"},
    66: {"name": "MESH_REJECTED_SAE",          "description": "Mesh SAE rejected",                                     "category": "security"},
    67: {"name": "MESH_REJECTED_8021X",        "description": "Mesh 802.1X rejected",                                  "category": "security"},
    68: {"name": "MESH_REJECTED_11R",          "description": "Mesh 802.11r FT rejected",                              "category": "security"},
    69: {"name": "UNSPECIFIED_DMG",            "description": "Unspecified DMG reason",                                "category": "dmg"},
    70: {"name": "DMG_AUTH_TIMEOUT",           "description": "DMG authentication timeout",                            "category": "dmg"},
    71: {"name": "UNSPECIFIED_FILS2",          "description": "Unspecified FILS reason 2",                             "category": "authentication"},
    72: {"name": "KEY_POLICY_VIOLATION",       "description": "Key policy violation",                                  "category": "security"},
    73: {"name": "KEY_ID_INVALID",             "description": "Key ID invalid for installed key",                      "category": "security"},
    74: {"name": "KEY_NOT_FOUND",              "description": "Key not found",                                         "category": "security"},
    75: {"name": "KEY_DESC_INVALID",           "description": "Key descriptor invalid",                                "category": "security"},
    76: {"name": "KEY_NOT_INSTALLED",          "description": "Key not installed",                                     "category": "security"},
    77: {"name": "KEY_OVERRUN",                "description": "Key identifier overrun",                                "category": "security"},
    78: {"name": "REPLAY_DETECTED",            "description": "Replay detected",                                       "category": "security"},
    79: {"name": "KEY_EXPIRED",                "description": "Key expired",                                           "category": "security"},
    80: {"name": "KEY_STATE_INVALID",          "description": "Key state invalid for operation",                       "category": "security"},
    81: {"name": "REKEY_FAILURE",              "description": "Rekey failure",                                         "category": "security"},
    82: {"name": "MIC_MISSING",                "description": "MIC missing in frame",                                  "category": "security"},
    83: {"name": "PN_UNAVAILABLE",             "description": "PN unavailable",                                         "category": "security"},
    84: {"name": "PN_INVALID",                 "description": "PN invalid for installed key",                          "category": "security"},
    85: {"name": "PN_REPLAY",                  "description": "PN replay detected",                                    "category": "security"},
    86: {"name": "PN_EXHAUSTED",               "description": "PN exhausted",                                          "category": "security"},
    87: {"name": "KEY_TX_ERROR",               "description": "Key TX error",                                          "category": "security"},
    88: {"name": "KEY_RX_ERROR",               "description": "Key RX error",                                          "category": "security"},
    89: {"name": "KEY_LIFETIME_EXPIRED",       "description": "Key lifetime expired",                                  "category": "security"},
    90: {"name": "KEY_USAGE_VIOLATION",        "description": "Key usage violation",                                   "category": "security"},
    91: {"name": "KEY_AGREEMENT_ERROR",        "description": "Key agreement error",                                   "category": "security"},
    92: {"name": "KEY_AUTH_FAILURE",           "description": "Key authentication failure",                            "category": "security"},
    93: {"name": "KEY_TOO_MANY_ATTEMPTS",      "description": "Too many key attempts",                                 "category": "security"},
    94: {"name": "KEY_RESERVED1",              "description": "Reserved reason code",                                  "category": "reserved"},
    95: {"name": "KEY_RESERVED2",              "description": "Reserved reason code",                                  "category": "reserved"},
    96: {"name": "KEY_RESERVED3",              "description": "Reserved reason code",                                  "category": "reserved"},
    97: {"name": "SAE_PASSWORD_ID_INVALID",    "description": "SAE password identifier is invalid",                    "category": "security"},
    98: {"name": "SAE_AUTH_REJECTED",          "description": "SAE authentication rejected",                           "category": "security"},
    99: {"name": "UNSPECIFIED_SAE",            "description": "Unspecified SAE reason",                                "category": "security"},
}

# ── 802.11 Status Codes (0-80) ──────────────────────────────────────────
STATUS_CODES: Dict[int, Dict] = {
    0:  {"name": "SUCCESS",                     "description": "Successful operation",                                   "category": "success"},
    1:  {"name": "UNSPECIFIED_FAILURE",          "description": "Unspecified failure",                                    "category": "failure"},
    2:  {"name": "TDLS_REJECTED_ALT",            "description": "TDLS rejected - alternative setup available",            "category": "tdls"},
    3:  {"name": "TDLS_REJECTED_FORBIDDEN",      "description": "TDLS rejected - not permitted",                          "category": "tdls"},
    4:  {"name": "TDLS_REJECTED_CHANNEL",        "description": "TDLS rejected - channel unacceptable",                   "category": "tdls"},
    5:  {"name": "SEC_DISABLED",                 "description": "Security disabled",                                      "category": "security"},
    6:  {"name": "UNSPECIFIED_QOS_FAILURE",      "description": "Unspecified QoS failure",                                "category": "qos"},
    7:  {"name": "REQUEST_DECLINED",             "description": "Request declined",                                       "category": "general"},
    8:  {"name": "REQUEST_TIMEOUT",              "description": "Request timed out",                                      "category": "timeout"},
    9:  {"name": "UNSPECIFIED_11H_FAILURE",      "description": "Unspecified 802.11h failure",                            "category": "spectrum"},
    10: {"name": "SPEC_MGMT_REJECTED",           "description": "Spectrum management rejected",                           "category": "spectrum"},
    11: {"name": "REFUSED_BAD_PARAMS",           "description": "Request refused - bad parameters",                       "category": "general"},
    12: {"name": "REJECTED_BAD_BSS",             "description": "Request rejected - bad BSS",                             "category": "association"},
    13: {"name": "REJECTED_NOT_PRESENT",         "description": "STA not present in BSS",                                 "category": "association"},
    14: {"name": "REJECTED_POWER_CAP",           "description": "Rejected - power capability unacceptable",               "category": "capability"},
    15: {"name": "REJECTED_CHANNELS",            "description": "Rejected - supported channels unacceptable",             "category": "capability"},
    16: {"name": "REJECTED_SHORT_SLOT",          "description": "Rejected - short slot time required",                    "category": "capability"},
    17: {"name": "REJECTED_DSSS_OFDM",           "description": "Rejected - DSSS-OFDM required",                          "category": "capability"},
    18: {"name": "REJECTED_MFP_POLICY",          "description": "Rejected - MFP policy violation",                        "category": "security"},
    19: {"name": "REJECTED_SPECTRUM_MGMT",       "description": "Rejected - spectrum management required",                "category": "spectrum"},
    20: {"name": "REJECTED_PBCC",               "description": "Rejected - PBCC modulation required",                    "category": "capability"},
    21: {"name": "REJECTED_CHANNEL_AGILITY",     "description": "Rejected - channel agility required",                    "category": "capability"},
    22: {"name": "REJECTED_SHORT_PREAMBLE",      "description": "Rejected - short preamble required",                     "category": "capability"},
    23: {"name": "REJECTED_PBCC_AND_AGILITY",    "description": "Rejected - PBCC and channel agility required",           "category": "capability"},
    24: {"name": "REJECTED_NO_SHORT_SLOT",       "description": "Rejected - no short slot time",                          "category": "capability"},
    25: {"name": "REJECTED_DSSS_OFDM_CAP",       "description": "Rejected - DSSS-OFDM capability required",               "category": "capability"},
    26: {"name": "REJECTED_HT_FEATURES",         "description": "Rejected - HT features not supported",                   "category": "capability"},
    27: {"name": "REJECTED_NO_QOS",              "description": "Rejected - QoS not supported",                           "category": "qos"},
    28: {"name": "REJECTED_NO_HT",              "description": "Rejected - HT not supported",                            "category": "capability"},
    29: {"name": "REJECTED_NO_HT_CHANNEL",       "description": "Rejected - HT channel width not supported",              "category": "capability"},
    30: {"name": "REJECTED_NO_RIFS",             "description": "Rejected - RIFS not supported",                          "category": "capability"},
    31: {"name": "REJECTED_NO_40MHZ",            "description": "Rejected - 40 MHz not supported",                        "category": "capability"},
    32: {"name": "REJECTED_NO_20_40_COEX",       "description": "Rejected - 20/40 coexistence not supported",             "category": "capability"},
    33: {"name": "REJECTED_NO_20MHZ_OFFSET",     "description": "Rejected - 20 MHz offset not supported",                 "category": "capability"},
    34: {"name": "REJECTED_NO_DSSS_CCK",         "description": "Rejected - DSSS/CCK not supported in HT",               "category": "capability"},
    35: {"name": "REJECTED_NO_FORTY_MHZ_INTOL",  "description": "Rejected - 40 MHz intolerant",                           "category": "capability"},
    36: {"name": "REJECTED_NO_OBSS_SCAN",        "description": "Rejected - OBSS scan not supported",                     "category": "capability"},
    37: {"name": "REJECTED_NO_20MHZ_INTOL",      "description": "Rejected - 20 MHz intolerant in HT",                     "category": "capability"},
    38: {"name": "REJECTED_LSIG_TXOP",           "description": "Rejected - L-SIG TXOP protection required",             "category": "capability"},
    39: {"name": "ASSOC_DENIED_QOS_UNSPECIFIED", "description": "Association denied - unspecified QoS reason",              "category": "qos"},
    40: {"name": "ASSOC_DENIED_NO_BANDWIDTH",    "description": "Association denied - insufficient bandwidth",             "category": "qos"},
    41: {"name": "ASSOC_DENIED_POOR_CHANNEL",    "description": "Association denied - poor channel conditions",            "category": "qos"},
    42: {"name": "ASSOC_DENIED_QOS_STA_LEAVING", "description": "Association denied - QoS STA leaving",                    "category": "qos"},
    43: {"name": "ASSOC_DENIED_QOS_POLICY",      "description": "Association denied - QoS policy",                         "category": "qos"},
    44: {"name": "ASSOC_DENIED_QOS_DELAY",       "description": "Association denied - QoS delay requirement",             "category": "qos"},
    45: {"name": "ASSOC_DENIED_QOS_SLO",         "description": "Association denied - QoS SLO requirement",               "category": "qos"},
    46: {"name": "ASSOC_DENIED_QOS_SSB",         "description": "Association denied - QoS SSB requirement",               "category": "qos"},
    47: {"name": "ASSOC_DENIED_QOS_TSPEC",       "description": "Association denied - TSPEC parameters",                  "category": "qos"},
    48: {"name": "ASSOC_DENIED_QOS_TSID",        "description": "Association denied - invalid TSID",                      "category": "qos"},
    49: {"name": "ASSOC_DENIED_QOS_AC",          "description": "Association denied - AC invalid",                        "category": "qos"},
    50: {"name": "ASSOC_DENIED_QOS_TCLAS",       "description": "Association denied - TCLAS processing",                  "category": "qos"},
    51: {"name": "ASSOC_DENIED_QOS_SCHEDULE",    "description": "Association denied - schedule conflict",                 "category": "qos"},
    52: {"name": "ASSOC_DENIED_QOS_TRAFFIC",     "description": "Association denied - traffic not scheduled",             "category": "qos"},
    53: {"name": "ASSOC_DENIED_VHT_FEATURES",    "description": "Association denied - VHT features required",             "category": "capability"},
    54: {"name": "ASSOC_DENIED_VHT_CHANNEL",     "description": "Association denied - VHT channel width",                 "category": "capability"},
    55: {"name": "ASSOC_DENIED_VHT_OP_CLASS",    "description": "Association denied - VHT operating class",               "category": "capability"},
    56: {"name": "ASSOC_DENIED_NO_VHT",          "description": "Association denied - VHT not supported",                 "category": "capability"},
    57: {"name": "ASSOC_DENIED_NO_160MHZ",       "description": "Association denied - 160 MHz not supported",             "category": "capability"},
    58: {"name": "ASSOC_DENIED_NO_160_80_80",    "description": "Association denied - 160+80+80 not supported",           "category": "capability"},
    59: {"name": "FILS_AUTH_REJECTED",           "description": "FILS authentication rejected",                           "category": "authentication"},
    60: {"name": "FILS_AUTH_TIMEOUT",            "description": "FILS authentication timeout",                            "category": "authentication"},
    61: {"name": "FILS_AUTH_SERVER_UNREACH",     "description": "FILS auth server unreachable",                           "category": "authentication"},
    62: {"name": "ASSOC_DENIED_HE_FEATURES",     "description": "Association denied - HE features required",              "category": "capability"},
    63: {"name": "ASSOC_DENIED_NO_HE",           "description": "Association denied - HE not supported",                  "category": "capability"},
    64: {"name": "ASSOC_DENIED_HE_CHANNEL",      "description": "Association denied - HE channel width",                  "category": "capability"},
    65: {"name": "ASSOC_DENIED_HE_OP_CLASS",     "description": "Association denied - HE operating class",                "category": "capability"},
    66: {"name": "ASSOC_DENIED_NO_6GHZ",         "description": "Association denied - 6 GHz not supported",               "category": "capability"},
    67: {"name": "ASSOC_DENIED_HE_6GHZ",         "description": "Association denied - HE 6 GHz required",                 "category": "capability"},
    68: {"name": "ASSOC_DENIED_SAE_AUTH",        "description": "Association denied - SAE authentication failed",         "category": "security"},
    69: {"name": "ASSOC_DENIED_SAE_HASH",        "description": "Association denied - SAE hash element rejected",         "category": "security"},
    70: {"name": "ASSOC_DENIED_OWE",             "description": "Association denied - OWE DH parameter rejected",         "category": "security"},
    71: {"name": "ASSOC_DENIED_NO_OWE",          "description": "Association denied - OWE not supported",                 "category": "security"},
    72: {"name": "ASSOC_DENIED_EHT_FEATURES",    "description": "Association denied - EHT features required",             "category": "capability"},
    73: {"name": "ASSOC_DENIED_NO_EHT",          "description": "Association denied - EHT not supported",                 "category": "capability"},
    74: {"name": "ASSOC_DENIED_EHT_CHANNEL",     "description": "Association denied - EHT channel width",                 "category": "capability"},
    75: {"name": "ASSOC_DENIED_EHT_OP_CLASS",    "description": "Association denied - EHT operating class",               "category": "capability"},
    76: {"name": "ASSOC_DENIED_EHT_320MHZ",      "description": "Association denied - EHT 320 MHz not supported",         "category": "capability"},
    77: {"name": "ASSOC_DENIED_MLO",             "description": "Association denied - MLO not supported",                 "category": "capability"},
    78: {"name": "ASSOC_DENIED_MLO_LINK",        "description": "Association denied - MLO link rejected",                 "category": "capability"},
    79: {"name": "ASSOC_DENIED_MLO_PARAM",       "description": "Association denied - MLO parameter invalid",             "category": "capability"},
    80: {"name": "REQUESTED_TCLAS_NOT_SUPPORTED","description": "Requested TCLAS not supported",                          "category": "qos"},
}


def get_reason_code(code: int) -> Optional[Dict]:
    """Get 802.11 reason code definition.

    Args:
        code: Reason code number (1-99).

    Returns:
        Dict with name, description, category, or None if not found.
    """
    return REASON_CODES.get(code)


def get_status_code(code: int) -> Optional[Dict]:
    """Get 802.11 status code definition.

    Args:
        code: Status code number (0-80).

    Returns:
        Dict with name, description, category, or None if not found.
    """
    return STATUS_CODES.get(code)


def get_reason_codes_by_category(category: str) -> Dict[int, Dict]:
    """Get all reason codes for a category.

    Args:
        category: Category name (e.g., "security", "qos", "mesh").

    Returns:
        Dict of code -> definition for matching reason codes.
    """
    return {
        code: info for code, info in REASON_CODES.items()
        if info.get("category") == category
    }


def get_status_codes_by_category(category: str) -> Dict[int, Dict]:
    """Get all status codes for a category.

    Args:
        category: Category name (e.g., "security", "qos", "capability").

    Returns:
        Dict of code -> definition for matching status codes.
    """
    return {
        code: info for code, info in STATUS_CODES.items()
        if info.get("category") == category
    }


def is_security_reason(code: int) -> bool:
    """Check if a reason code is security-related.

    Args:
        code: Reason code number.

    Returns:
        True if the reason code is in the security category.
    """
    info = REASON_CODES.get(code)
    return info is not None and info.get("category") == "security"
