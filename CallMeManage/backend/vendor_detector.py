vendors_list = [
    "cisco",
    "juniper",
    "junos",
    "huawei"
]

def vender_detector(capabilities: list[str]) -> str:
    capa_detail = " ".join(capabilities).lower()
    for vendor in vendors_list:
        if vendor in capa_detail:
            return vendor
    return "unknown"
