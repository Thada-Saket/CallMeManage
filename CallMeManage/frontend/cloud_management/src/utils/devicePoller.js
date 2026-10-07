// |====== Polling ที่ไม่ซ้อนกัน + backoff (หน้า Devices) ======|
// ใช้ setTimeout ต่อกันหลัง request ก่อนหน้า "จบ" แล้วเท่านั้น (ไม่ใช้ setInterval) จึงไม่มี request ทับกัน
// สำเร็จ -> กลับไปรอบปกติ, ล้มเหลว -> คูณ 2 ไม่เกิน maxMs (10 -> 20 -> 40 -> 60 วินาที)
// stop() ล้าง timer และทำให้ผลของ request ที่ค้างอยู่ถูกทิ้ง (ไม่ตั้งรอบถัดไป)

export const POLL_BASE_MS = 10000;
export const POLL_MAX_MS = 60000;

export function nextPollDelay(currentMs, ok, baseMs = POLL_BASE_MS, maxMs = POLL_MAX_MS) {
  return ok ? baseMs : Math.min(currentMs * 2, maxMs);
}

// run() คืน false = ล้มเหลว (หรือ throw), ค่าอื่น = สำเร็จ
export function createPoller({
  run,
  baseMs = POLL_BASE_MS,
  maxMs = POLL_MAX_MS,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
}) {
  let timer = null;
  let delay = baseMs;
  let running = false;
  let stopped = true;
  let generation = 0;

  function schedule(gen) {
    timer = setTimer(() => tick(gen), delay);
  }

  async function tick(gen) {
    timer = null;
    if (stopped || gen !== generation) return;
    running = true;
    let ok = false;
    try {
      ok = (await run()) !== false;
    } catch {
      ok = false;
    }
    running = false;
    if (stopped || gen !== generation) return; // ถูก stop ระหว่างรอ: ไม่ตั้งรอบถัดไป
    delay = nextPollDelay(delay, ok, baseMs, maxMs);
    schedule(gen);
  }

  return {
    start() {
      if (!stopped) return;
      stopped = false;
      generation += 1;
      delay = baseMs;
      schedule(generation);
    },
    stop() {
      stopped = true;
      generation += 1;
      if (timer !== null) clearTimer(timer);
      timer = null;
    },
    get delay() {
      return delay;
    },
    get running() {
      return running;
    },
    get active() {
      return !stopped;
    },
  };
}

// |====== กัน response ของ Site เก่า/หน้าที่ปิดแล้วมาเขียนทับ state ======|
// advance() เรียกทุกครั้งที่ site_id เปลี่ยน (และตอน cleanup) - response ที่ถือ generation เก่าจะ isCurrent() = false
export function createGenerationGuard() {
  let value = 0;
  return {
    advance() {
      value += 1;
      return value;
    },
    isCurrent(generation) {
      return generation === value;
    },
    get value() {
      return value;
    },
  };
}
