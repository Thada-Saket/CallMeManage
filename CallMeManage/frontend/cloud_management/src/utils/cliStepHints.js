// คำอธิบายสั้น ๆ ใต้หัวข้อแต่ละขั้นของ CLI Generator ว่าคัดลอกไปวางแล้วได้อะไร - อิงตาม
// id ที่ backend ส่งมา (backend/cli_generator.py, callhome_identity_writer.py)
// id ที่ไม่มีในนี้ไม่แสดงคำอธิบาย แค่มีเลขขั้นตามปกติ
const CLI_STEP_HINTS = {
  "initial-config": "Sets the hostname, login and WAN address so the device can reach the server.",
  "wan-security-zone": "Allows DHCP, ping, SSH and NETCONF on the WAN port. Run commit after pasting.",
  "load-config-file": "Downloads the management config from the server to the device.",
  "copy-config-running": "Applies the downloaded config. The device then connects to the server.",
  "load-config-candidate": "Loads the downloaded config, ready to commit.",
  "local-administrator": "Adds the local administrator account you set in the form.",
  "commit-check": "Checks the config for errors. If it passes, run commit and the device connects to the server.",
  "recovery-callhome-endpoint": "Points the device back to this server so it reconnects.",
  "recovery-outbound-ssh-client": "Points the device back to this server so it reconnects.",
};

export function cliStepHint(stepId) {
  return CLI_STEP_HINTS[stepId] || "";
}
