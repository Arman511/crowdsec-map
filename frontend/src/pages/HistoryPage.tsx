import type * as React from "react";

export function HistoryPage({
  HistoryView,
}: {
  HistoryView: React.ComponentType<Record<string, unknown>>;
}) {
  return <HistoryView />;
}
