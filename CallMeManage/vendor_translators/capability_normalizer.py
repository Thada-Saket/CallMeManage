"""แปลง reply ของคำสั่งตรวจความสามารถอุปกรณ์ให้เป็นข้อมูลสำหรับโปรไฟล์

แยกออกจาก response_normalizer.py เพราะคำสั่งกลุ่มนี้ไม่ใช่คำสั่งสาธารณะ (ไม่อยู่ใน
PUBLIC_FUNCTIONS และ NORMALIZERS) ผู้เรียกคือระบบตรวจความสามารถตอน call-home เท่านั้น
ดีไซน์อยู่ที่ planning/capability_detection_notes.txt หัวข้อ 9

ทุกฟังก์ชันคืน dict ที่มี "status" เสมอและไม่ raise - ตรวจไม่สำเร็จต้องไม่ทำให้ call-home
ล้ม และผู้เรียกต้องแยก "ตรวจไม่สำเร็จ" (failed) ออกจาก "อุปกรณ์ไม่มีค่านี้" ได้ เพราะหลักของ
ระบบคือซ่อนเมนูเฉพาะเมื่อมีหลักฐานว่าทำไม่ได้
"""
from xml.etree import ElementTree as ET

from tools.safe_xml import safe_fromstring
from vendor_translators.response_normalizer import _local_name, collect_rpc_errors


def _failed(message: str, errors: list[dict] | None = None) -> dict:
    return {"status": "failed", "message": message, "errors": errors or []}


def _parse_reply(xml_response: str):
    """คืน (root, None) ถ้าใช้ได้ หรือ (None, ผลล้มเหลว)"""
    try:
        root = safe_fromstring(xml_response.strip())
    except (ET.ParseError, AttributeError) as exc:
        return None, _failed(f"Cannot parse XML: {exc}")
    # rpc-error ระดับ warning มาคู่กับข้อมูลได้ตาม RFC 6241 §4.3 จึงนับเฉพาะ error จริง
    errors = [error for error in collect_rpc_errors(root) if error.get("severity") != "warning"]
    if errors:
        return None, _failed("Device replied with rpc-error", errors)
    return root, None


def _children(element, name: str) -> list:
    return [child for child in element if _local_name(child.tag) == name]


def _child_value(element, name: str) -> str | None:
    for child in _children(element, name):
        if child.text and child.text.strip():
            return child.text.strip()
    return None


def summarize_schema_modules(source: str, modules: list[dict]) -> dict:
    """ส่วนที่ไม่ขึ้นกับ XML: รับ [{"name", "namespace", "features"}] แล้วสรุปเป็นชุด namespace
    กับ feature ต่อ module - แยกไว้ให้ทดสอบกับ capture ที่เก็บเป็น JSON ได้ด้วย"""
    namespaces = set()
    features: dict[str, set] = {}
    for module in modules:
        if module.get("namespace"):
            namespaces.add(module["namespace"])
        if module.get("name") and module.get("features"):
            features.setdefault(module["name"], set()).update(module["features"])
    if not namespaces:
        return _failed("No module list found in reply")
    return {
        "status": "ok",
        "source": source,
        "module_count": len(modules),
        "namespaces": sorted(namespaces),
        "features": {name: sorted(values) for name, values in sorted(features.items())},
    }


def parse_capability_schema(xml_response: str) -> dict:
    """reply ของ get_capability_schema - Cisco ตอบ ietf-yang-library (มี feature),
    Huawei/Juniper ตอบ ietf-netconf-monitoring (มีแค่ identifier + namespace)"""
    root, failure = _parse_reply(xml_response)
    if failure:
        return failure

    for element in root.iter():
        name = _local_name(element.tag)
        if name == "yang-library":
            modules = []
            for module_set in _children(element, "module-set"):
                # import-only-module นับด้วย เพราะ namespace ของมันถูกอ้างใน payload ได้
                for module in _children(module_set, "module") + _children(module_set, "import-only-module"):
                    modules.append({
                        "name": _child_value(module, "name"),
                        "namespace": _child_value(module, "namespace"),
                        "features": [
                            feature.text.strip()
                            for feature in _children(module, "feature")
                            if feature.text and feature.text.strip()
                        ],
                    })
            result = summarize_schema_modules("yang-library", modules)
            if result["status"] == "ok":
                result["content_id"] = _child_value(element, "content-id")
            return result
        if name == "netconf-state":
            modules = [
                {"name": _child_value(schema, "identifier"), "namespace": _child_value(schema, "namespace"), "features": []}
                for schemas in _children(element, "schemas")
                for schema in _children(schemas, "schema")
            ]
            return summarize_schema_modules("netconf-monitoring", modules)

    return _failed("Reply contains neither yang-library nor netconf-state")


def extract_content_id(capabilities: list[str]) -> str | None:
    """ตัวระบุชุด schema จาก hello (yang-library capability) ใช้ข้ามการดึง schema ซ้ำเมื่อไม่เปลี่ยน
    ใช้ content-id (yang-library:1.1) ก่อน ถ้าไม่มีจึงใช้ module-set-id (yang-library:1.0)"""
    fallback = None
    for capability in capabilities or []:
        if "capability:yang-library:" not in capability or "?" not in capability:
            continue
        for pair in capability.split("?", 1)[1].replace("&amp;", "&").split("&"):
            key, _, value = pair.partition("=")
            if key == "content-id" and value:
                return value
            if key == "module-set-id" and value and fallback is None:
                fallback = value
    return fallback


def parse_boot_license(xml_response: str) -> dict:
    """reply ของ Cisco get_boot_license - level เป็น choice ใน Cisco-IOS-XE-license.yang
    ลูกมีได้ทั้ง container ที่มี addon (network-advantage) และ leaf ว่าง (AdvUCSuiteK9)
    จึงอ่านชื่อลูกตัวแรกแบบทั่วไป; ไม่มี level = ยังไม่ได้ config (not_configured) ไม่ใช่ล้มเหลว"""
    root, failure = _parse_reply(xml_response)
    if failure:
        return failure

    for license_element in root.iter():
        if _local_name(license_element.tag) != "license":
            continue
        for boot in _children(license_element, "boot"):
            for level in _children(boot, "level"):
                for choice in level:
                    return {
                        "status": "ok",
                        "level": _local_name(choice.tag),
                        "addon": _child_value(choice, "addon"),
                    }
    return {"status": "not_configured", "level": None, "addon": None}


def parse_route_engine_model(xml_response: str) -> dict:
    """รุ่นเครื่อง Juniper จาก reply ของ get_cpu_memory_information (get-route-engine-information)
    ยังไม่เคย capture ค่าจริงของ vSRX - ตารางข้อยกเว้นต้องรอค่าจริงก่อนใช้"""
    root, failure = _parse_reply(xml_response)
    if failure:
        return failure

    for element in root.iter():
        if _local_name(element.tag) == "route-engine":
            model = _child_value(element, "model")
            if model:
                return {"status": "ok", "value": model}
    return {"status": "not_found", "value": None}
