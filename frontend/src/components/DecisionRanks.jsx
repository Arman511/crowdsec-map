export function DecisionRanks({ title, items }) {
    return (
        <div><strong>{title}</strong><span>{items.slice(0, 5).map((item) => `${item.label} ${item.count}`).join(" · ") || "No data"}</span></div>
    );
}
