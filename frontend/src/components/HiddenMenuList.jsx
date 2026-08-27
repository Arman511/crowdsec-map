export function HiddenMenuList({ title, items }) {
  return (
    <div className="hiddenMenuList">
      <h4>{title}</h4>
      {items.slice(0, 8).map((item) => (
        <div className="hiddenMenuListRow" key={item.label}>
          <span title={item.label}>{item.label}</span>
          <strong>{item.count}</strong>
        </div>
      ))}
      {items.length === 0 && <p>No data.</p>}
    </div>
  );
}
