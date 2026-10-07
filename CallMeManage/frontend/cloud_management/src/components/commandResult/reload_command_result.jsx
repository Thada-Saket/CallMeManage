export function Reload_Result({ loading = false, onRefresh = () => {} }) {
    return (
        <>
            <div></div>
            <button type="button" className="btn-refresh btn-ghost" disabled={loading} onClick={onRefresh}>
                &#x27F3;
            </button>
        </>
    )
}
