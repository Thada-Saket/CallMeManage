// Component แถบ tab สำหรับสลับหน้า/ส่วนของเนื้อหา (UI/Layout ร่วม)
// ออกแบบตามมาตรฐาน WAI-ARIA (tablist, tab, aria-selected)
export default function PageTabs({ tabs = [], activeId, onChange, ariaLabel = "Navigation Tabs" }) {
  if (!Array.isArray(tabs) || tabs.length === 0) return null;

  function handleKeyDown(e, currentIndex) {
    let nextIndex = null;
    if (e.key === "ArrowRight") {
      nextIndex = (currentIndex + 1) % tabs.length;
    } else if (e.key === "ArrowLeft") {
      nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    } else if (e.key === "Home") {
      nextIndex = 0;
    } else if (e.key === "End") {
      nextIndex = tabs.length - 1;
    }

    if (nextIndex !== null) {
      e.preventDefault();
      const nextTab = tabs[nextIndex];
      if (nextTab && onChange) {
        onChange(nextTab.id);
        const nextBtn = document.getElementById(`tab-${nextTab.id}`);
        if (nextBtn) nextBtn.focus();
      }
    }
  }

  return (
    <div className="page-tabs-container">
      <div role="tablist" className="page-tabs-list" aria-label={ariaLabel}>
        {tabs.map((tab, index) => {
          const isActive = tab.id === activeId;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={`tab-${tab.id}`}
              aria-selected={isActive}
              aria-controls={`tabpanel-${tab.id}`}
              tabIndex={isActive ? 0 : -1}
              className={`page-tab-button ${isActive ? "active" : ""}`}
              onClick={() => onChange && onChange(tab.id)}
              onKeyDown={(e) => handleKeyDown(e, index)}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
