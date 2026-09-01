import type { Alert, ActiveBan, AttacksResponse } from "../types";

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
  filterOptions: Record<string, any>;
  filters: Record<string, string>;
  loading: boolean;
  mapExpanded: boolean;
  onCloseEvent: () => void;
  onCloseMap: () => void;
  onEventDrilldown: (bucket: any) => void;
  onExpandMap: () => void;
  onInvestigate: (detail: any) => void;
  onSelectEvent: (e: Alert) => void;
  onSelectMapGroup: (g: any) => void;
  onSetFilters: (f: Record<string, string>) => void;
  onInspectMap?: (detail: any) => void;
  selectedEvent?: Alert;
  selectedMapGroup?: any;
  eventDrilldown?: any;
  EventCollectionDrawer: React.ComponentType<any>;
  EventDetailDrawer: React.ComponentType<any>;
  EventTable: React.ComponentType<any>;
  ExpandedMapModal: React.ComponentType<any>;
  LiveFilterBar: React.ComponentType<any>;
  ActivityTrend: React.ComponentType<any>;
  AgeLegend: React.ComponentType<any>;
  WorldMap: React.ComponentType<any>;
  Timeline: React.ComponentType<any>;
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
