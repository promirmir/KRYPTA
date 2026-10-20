"""Validate security-critical Android research-vault translations in all 11 locales."""
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1] / "android/app/src/main/res"
FOLDERS = ["values", "values-pl", "values-ru", "values-zh-rCN", "values-es",
           "values-ar", "values-hi", "values-pt", "values-fr", "values-de", "values-in"]
REQUIRED = {"vault_status", "vault_warning", "vault_body", "vault_encrypt",
            "vault_decrypt", "vault_idle", "vault_success", "vault_failed",
            "vault_cancelled", "vault_need_lock", "vault_auth_title",
            "vault_auth_body", "vault_same_file"}
def main():
    for folder in FOLDERS:
        path = ROOT / folder / "vault.xml"
        values = ET.parse(path).getroot()
        entries = values.findall("string")
        found = {x.attrib.get("name") for x in entries}
        if found != REQUIRED or len(entries) != len(REQUIRED):
            raise SystemExit(f"Incomplete Android vault locale: {path}")
        if not all(x.text and x.text.strip() for x in entries):
            raise SystemExit(f"Empty Android vault security string: {path}")
    print("KRYPTA mobile vault: all 11 locales have complete security/action strings")
if __name__ == "__main__":
    main()
