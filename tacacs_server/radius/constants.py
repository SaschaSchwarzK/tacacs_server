"""RADIUS Protocol Constants and Definitions.

This module contains all the standard RADIUS protocol constants as defined in
RFC 2865 (Authentication), RFC 2866 (Accounting), and related specifications.
It includes packet codes, attribute types, service types, and vendor-specific
attributes used throughout the RADIUS implementation.

Constants defined in this module are used to construct and parse RADIUS packets,
and to provide a clear understanding of the protocol's structure and behavior.
"""

# Standard RADIUS Packet Codes (RFC 2865 §4.1)
# These values represent the first octet of a RADIUS packet
RADIUS_ACCESS_REQUEST = 1  #: Access-Request packet code
RADIUS_ACCESS_ACCEPT = 2  #: Access-Accept packet code
RADIUS_ACCESS_REJECT = 3  #: Access-Reject packet code
RADIUS_ACCOUNTING_REQUEST = 4  #: Accounting-Request packet code
RADIUS_ACCOUNTING_RESPONSE = 5  #: Accounting-Response packet code
RADIUS_ACCESS_CHALLENGE = 11  #: Access-Challenge packet code

# Packet limits
MAX_RADIUS_PACKET_LENGTH = 4096  # RFC 2865 maximum

# Standard RADIUS Attribute Types (RFC 2865 §5)
# Format: ATTR_NAME = type_code  # RFC/Spec Reference
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_CHAP_PASSWORD = 3
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_SERVICE_TYPE = 6
ATTR_FRAMED_PROTOCOL = 7
ATTR_FRAMED_IP_ADDRESS = 8
ATTR_FILTER_ID = 11
ATTR_REPLY_MESSAGE = 18
ATTR_STATE = 24
ATTR_CLASS = 25
ATTR_VENDOR_SPECIFIC = 26
ATTR_SESSION_TIMEOUT = 27
ATTR_IDLE_TIMEOUT = 28
ATTR_CALLED_STATION_ID = 30
ATTR_CALLING_STATION_ID = 31
ATTR_NAS_IDENTIFIER = 32
ATTR_ACCT_STATUS_TYPE = 40
ATTR_ACCT_DELAY_TIME = 41
ATTR_ACCT_INPUT_OCTETS = 42
ATTR_ACCT_OUTPUT_OCTETS = 43
ATTR_ACCT_SESSION_ID = 44
ATTR_ACCT_AUTHENTIC = 45
ATTR_ACCT_SESSION_TIME = 46
ATTR_ACCT_INPUT_PACKETS = 47
ATTR_ACCT_OUTPUT_PACKETS = 48
ATTR_ACCT_TERMINATE_CAUSE = 49
ATTR_NAS_PORT_TYPE = 61
ATTR_MESSAGE_AUTHENTICATOR = 80

# Service Types (RFC 2865 §5.6)
# Used in Service-Type attribute to indicate the type of service requested
SERVICE_TYPE_LOGIN = 1
SERVICE_TYPE_FRAMED = 2
SERVICE_TYPE_CALLBACK_LOGIN = 3
SERVICE_TYPE_CALLBACK_FRAMED = 4
SERVICE_TYPE_OUTBOUND = 5
SERVICE_TYPE_ADMINISTRATIVE = 6
SERVICE_TYPE_NAS_PROMPT = 7

# Accounting Status Types (RFC 2866 §5.1)
# Used in Acct-Status-Type attribute to indicate accounting record type
ACCT_STATUS_START = 1
ACCT_STATUS_STOP = 2
ACCT_STATUS_INTERIM_UPDATE = 3
ACCT_STATUS_ACCOUNTING_ON = 7
ACCT_STATUS_ACCOUNTING_OFF = 8

# NAS Port Types
NAS_PORT_TYPE_ASYNC = 0
NAS_PORT_TYPE_SYNC = 1
NAS_PORT_TYPE_ISDN = 2
NAS_PORT_TYPE_ISDN_V120 = 3
NAS_PORT_TYPE_ISDN_V110 = 4
NAS_PORT_TYPE_VIRTUAL = 5
NAS_PORT_TYPE_ETHERNET = 15
NAS_PORT_TYPE_WIRELESS = 19

# Vendor IDs (RFC 2865 §5.26)
VENDOR_CISCO = 9
VENDOR_JUNIPER = 2636
VENDOR_MICROSOFT = 311
VENDOR_ARISTA = 30065
VENDOR_PALO_ALTO = 25461
VENDOR_FORTINET = 12356
VENDOR_PFSENSE = 19082
VENDOR_CHECKPOINT = 2620
VENDOR_EXTREME = 1916

# Cisco VSA Attribute Types (Vendor-Id: 9)
CISCO_AVPAIR = 1  # Cisco-AVPair (shell:priv-lvl=15, etc.)
CISCO_NAS_PORT = 2
CISCO_ACCOUNT_INFO = 250
