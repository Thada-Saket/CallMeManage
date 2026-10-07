// |====== Pagination Button (ก่อนหน้า/ถัดไป) ======|
// ไม่มีเลขหน้า เพราะฝั่ง Devices.jsx ใช้ cursor + prefetch แทน
// ไม่รู้จำนวนหน้าทั้งหมดล่วงหน้า รู้แค่ "มีชุดถัดไปไหม" (hasNext) กับ "อยู่ชุดแรกหรือยัง" (hasPrev)
import '../assets/css/pagination.css'

export function Pagination({ hasPrev, hasNext, onPrev, onNext }) {
  // ไม่มีทั้งก่อนหน้าและถัดไป (มีข้อมูลแค่ชุดเดียว) ไม่ต้องแสดงปุ่มเลย
  if (!hasPrev && !hasNext) {
    return null;
  }

  return (
    <div className="pagination-container">
      <button 
        type="button" 
        onClick={onPrev} 
        disabled={!hasPrev} 
        className="paginate-btn"
        aria-label="Previous"
      >
        &#x2190;
      </button>
      <button 
        type="button" 
        onClick={onNext} 
        disabled={!hasNext} 
        className="paginate-btn"
        aria-label="Next"
      >
        &#x2192;
      </button>
    </div>
  );
}
