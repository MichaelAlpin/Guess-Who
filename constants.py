# Source: https://subinsb.com/default-device-ttl-values/
OS_TTL_VALUES = {
    "AIX": {"TCP": [60], "UDP": [30], "ICMP": [255]},
    "BSDI": {"TCP": [], "UDP": [], "ICMP": [255]},
    "Cisco": {"TCP": [], "UDP": [], "ICMP": [254]},
    "DEC Pathworks": {"TCP": [30], "UDP": [30], "ICMP": []},
    "Foundry": {"TCP": [], "UDP": [], "ICMP": [64]},
    "FreeBSD": {"TCP": [64], "UDP": [64], "ICMP": [64, 255]},
    "HP-UX": {"TCP": [30, 64], "UDP": [30, 64], "ICMP": [255]},
    "Irix": {"TCP": [60], "UDP": [60], "ICMP": [255]},
    "juniper": {"TCP": [], "UDP": [], "ICMP": [64]},
    "MPE/IX (HP)": {"TCP": [], "UDP": [], "ICMP": [200]},
    "Linux": {"TCP": [64], "UDP": [], "ICMP": [64, 255]},
    "MacOS/MacTCP": {"TCP": [60, 64], "UDP": [60, 64], "ICMP": [64]},
    "NetBSD": {"TCP": [], "UDP": [], "ICMP": [255]},
    "Netgear FVG318": {"TCP": [], "UDP": [64], "ICMP": [64]},
    "OpenBSD": {"TCP": [], "UDP": [], "ICMP": [255]},
    "OpenVMS": {"TCP": [], "UDP": [], "ICMP": [255]},
    "OSF/1": {"TCP": [60], "UDP": [30], "ICMP": []},
    "Solaris": {"TCP": [30, 60, 64], "UDP": [30, 60, 64], "ICMP": [60, 255]},
    "SunOS": {"TCP": [60, 255], "UDP": [60], "ICMP": [255]},
    "Ultrix": {"TCP": [60], "UDP": [30], "ICMP": [255]},
    "VMS/Multinet": {"TCP": [64], "UDP": [64], "ICMP": []},
    "VMS/TCPware": {"TCP": [60], "UDP": [64], "ICMP": []},
    "VMS/Wollongong": {"TCP": [128], "UDP": [30], "ICMP": []},
    "VMS/UCX": {"TCP": [128], "UDP": [128], "ICMP": []},
    "Windows": {"TCP": [32, 128], "UDP": [32, 128], "ICMP": [32, 128]},
}

# Source: https://www.cs.dartmouth.edu/~sergey/netreads/ICMP_Scanning_v3.0.pdf
OS_STATS = [
    {
        "OS": "Windows",
        "ICMP_DATA_LENGTH": 32,
        "ICMP_SEQ_START": 256,
        "ICMP_SEQ_GAP": 256,
    },
    {"OS": "Linux", "ICMP_DATA_LENGTH": 56, "ICMP_SEQ_START": 0, "ICMP_SEQ_GAP": 256},
    {"OS": "FreeBSD", "ICMP_DATA_LENGTH": 56, "ICMP_SEQ_START": 0, "ICMP_SEQ_GAP": 256},
    {"OS": "AIX", "ICMP_DATA_LENGTH": 56, "ICMP_SEQ_START": 0, "ICMP_SEQ_GAP": 1},
    {
        "OS": "Sun Solaris",
        "ICMP_DATA_LENGTH": 56,
        "ICMP_SEQ_START": 0,
        "ICMP_SEQ_GAP": 1,
    },
]

WINDOWS_ICMP_ID_VALUES = [256, 512, 768]
