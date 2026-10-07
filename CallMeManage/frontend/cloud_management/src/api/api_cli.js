import { request } from "./api_client";

// ส่งข้อมูลที่ผู้ใช้กรอกไปยัง backend เพื่อสร้าง cli เอาไปวางที่อุปกรณ์ เรียกใช้ใน CliGenerator.jsx
export function generateCli(payload) {
  return request("/cli/generate", { method: "POST", body: payload });
}

// backend บอก IP ของตัวเองให้เลย ไม่ต้องให้ user กรอก เรียกใช้ใน CliGenerator.jsx
export function getCliServerInfo() {
  return request("/cli/server-info");
}
