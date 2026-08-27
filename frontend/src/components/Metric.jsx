import React from "react";

export function Metric({ icon, label, value, onClick }) {
  const content = (
    <>
      {React.cloneElement(icon, { size: 18 })}
      <span>{label}</span>
      <strong>{value}</strong>
    </>
  );
  return onClick ? (
    <button
      type="button"
      className="metric metricButton"
      onClick={onClick}
      title={`Open ${label}`}
    >
      {content}
    </button>
  ) : (
    <div className="metric">{content}</div>
  );
}
