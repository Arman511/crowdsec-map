import React from "react";

export function Metric({
  icon,
  label,
  value,
  onClick,
}: {
  icon: React.ReactElement;
  label: string;
  value: React.ReactNode;
  onClick?: () => void;
}) {
  const content = (
    <>
      {React.cloneElement(icon, { size: 18 } as Record<string, unknown>)}
      <span>{label}</span>
      <strong>{value}</strong>
    </>
  );

  return onClick ? (
    <button type="button" className="metric metricButton" onClick={onClick} title={`Open ${label}`}>
      {content}
    </button>
  ) : (
    <div className="metric">{content}</div>
  );
}
