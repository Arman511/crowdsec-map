import type {
  ActiveBan,
  Alert,
  AttacksResponse,
  EventDrilldown,
  MapGroup,
  TimelineAttackGroup,
} from "../types";
import type * as React from "react";
import "../styles/pages/LivePage.scss";

type EventCollectionDrawerType = React.ComponentType<{
  detail: EventDrilldown;
  activeBans: ActiveBan[];
  onClose: () => void;
  onInvestigate: (d: string) => void;
}>;

type EventDetailDrawerType = React.ComponentType<{
  event: Alert;
  activeBans: ActiveBan[];
  onClose: () => void;
  onInvestigate: (detail: string) => void;
}>;

type EventTableType = React.ComponentType<{
  attacks: Alert[];
  activeBans: ActiveBan[];
  selectedEvent?: Alert;
  onSelectEvent: (e: Alert) => void;
}>;

type ExpandedMapModalType = React.ComponentType<{
  attacks: Alert[];
  error?: string;
  selectedGroup?: MapGroup;
  onSelectGroup: (g: MapGroup | null) => void;
  onClose: () => void;
  onInspect?: (detail: EventDrilldown) => void;
  onInvestigate?: (ip: string) => void;
  ActivityTrend: React.ComponentType<any>;
  Timeline: React.ComponentType<any>;
  WorldMap: React.ComponentType<any>;
}>;

type LiveFilterBarType = React.ComponentType<{
  filters: Record<string, string>;
  setFilters: (
    f: Record<string, string> | ((prev: Record<string, string>) => Record<string, string>),
  ) => void;
  options: Record<string, string[]>;
  resultCount: number;
  totalCount: number;
}>;

type ActivityTrendType = React.ComponentType<{
  attacks: Alert[];
  onSelectBucket: (bucket: { label: string; count: number; attacks: Alert[] }) => void;
}>;

type AgeLegendType = React.ComponentType<Record<string, never>>;

type WorldMapType = React.ComponentType<{
  attacks: Alert[];
  showPaths?: boolean;
  initialLoading?: boolean;
  expanded?: boolean;
  onExpand: () => void;
  onSelectPoint?: (g: MapGroup | null) => void;
}>;

type TimelineType = React.ComponentType<{
  attacks: Alert[];
  error?: string;
  onSelectGroup: (g: TimelineAttackGroup) => void;
}>;

export function LivePage({
  attacks,
  activeBans,
  data,
  error,
  filterOptions,
  filters,
  loading,
  mapExpanded,
  onCloseEvent,
  onCloseMap,
  onEventDrilldown,
  onExpandMap,
  onInvestigate,
  onSelectEvent,
  onSelectMapGroup,
  onSetFilters,
  onInspectMap,
  selectedEvent,
  selectedMapGroup,
  eventDrilldown,
  EventCollectionDrawer: EventCollectionDrawerComp,
  EventDetailDrawer: EventDetailDrawerComp,
  EventTable: EventTableComp,
  ExpandedMapModal: ExpandedMapModalComp,
  LiveFilterBar: LiveFilterBarComp,
  ActivityTrend: ActivityTrendComp,
  AgeLegend: AgeLegendComp,
  WorldMap: WorldMapComp,
  Timeline: TimelineComp,
}: {
  attacks: Alert[];
  activeBans: ActiveBan[];
  data?: AttacksResponse;
  error?: string;
  filterOptions: Record<string, string[]>;
  filters: Record<string, string>;
  loading: boolean;
  mapExpanded: boolean;
  onCloseEvent: () => void;
  onCloseMap: () => void;
  onEventDrilldown: (bucket: { label: string; count: number; attacks: Alert[] }) => void;
  onExpandMap: () => void;
  onInvestigate: (ip: string) => void;
  onSelectEvent: (e: Alert) => void;
  onSelectMapGroup: (g: MapGroup | null) => void;
  onSetFilters: (
    f: Record<string, string> | ((prev: Record<string, string>) => Record<string, string>),
  ) => void;
  onInspectMap?: (detail: EventDrilldown) => void;
  selectedEvent?: Alert;
  selectedMapGroup?: MapGroup;
  eventDrilldown?: EventDrilldown;
  EventCollectionDrawer: EventCollectionDrawerType;
  EventDetailDrawer: EventDetailDrawerType;
  EventTable: EventTableType;
  ExpandedMapModal: ExpandedMapModalType;
  LiveFilterBar: LiveFilterBarType;
  ActivityTrend: ActivityTrendType;
  AgeLegend: AgeLegendType;
  WorldMap: WorldMapType;
  Timeline: TimelineType;
}) {
  return (
    <>
      <LiveFilterBarComp
        filters={filters}
        setFilters={onSetFilters}
        options={filterOptions}
        resultCount={attacks.length}
        totalCount={data?.alerts?.length || 0}
      />
      <div className="liveMapStack">
        <WorldMapComp attacks={attacks} initialLoading={loading && !data} onExpand={onExpandMap} />
        <ActivityTrendComp attacks={attacks} onSelectBucket={onEventDrilldown} />
        <AgeLegendComp />
      </div>
      <EventTableComp
        attacks={attacks}
        activeBans={activeBans}
        selectedEvent={selectedEvent}
        onSelectEvent={onSelectEvent}
      />
      {selectedEvent && (
        <EventDetailDrawerComp
          event={selectedEvent}
          activeBans={activeBans}
          onClose={onCloseEvent}
          onInvestigate={onInvestigate}
        />
      )}
      {eventDrilldown && (
        <EventCollectionDrawerComp
          detail={eventDrilldown}
          activeBans={activeBans}
          onClose={onCloseEvent}
          onInvestigate={onInvestigate}
        />
      )}
      {mapExpanded && (
        <ExpandedMapModalComp
          attacks={attacks}
          error={error || data?.warning}
          selectedGroup={selectedMapGroup}
          onSelectGroup={onSelectMapGroup}
          onClose={onCloseMap}
          onInspect={onInspectMap}
          onInvestigate={onInvestigate}
          WorldMap={WorldMapComp}
          ActivityTrend={ActivityTrendComp}
          Timeline={TimelineComp}
        />
      )}
    </>
  );
}
