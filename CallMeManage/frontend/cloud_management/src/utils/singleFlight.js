// |====== กัน submit ซ้ำ (double click) ======|
// busy ถูกตั้งแบบ synchronous ก่อน await จึงกันคลิกที่สองที่เข้ามาในจังหวะเดียวกันได้จริง
// (state ของ React อย่าง `submitting` อัปเดตหลัง render จึงกันไม่ทัน)
export function createSingleFlight() {
  let busy = false;
  return {
    get busy() {
      return busy;
    },
    async run(task) {
      if (busy) return { skipped: true };
      busy = true;
      try {
        return { skipped: false, value: await task() };
      } finally {
        busy = false;
      }
    },
  };
}
