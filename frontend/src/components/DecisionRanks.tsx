import type { LabelCount } from "../types";

export function DecisionRanks({ title, items }: { title: string; items: LabelCount[] }) {
  return (
    <div>
      <strong>{title}</strong>
      <span>
        {items
          .slice(0, 5)
          .map((item: LabelCount) => `${item.label} ${item.count}`)
          .join(" · ") || "No data"}
      </span>
    </div>
  );
}
