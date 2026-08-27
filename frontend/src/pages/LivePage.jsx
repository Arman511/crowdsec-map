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
  EventCollectionDrawer,
  EventDetailDrawer,
  EventTable,
  ExpandedMapModal,
  LiveFilterBar,
  ActivityTrend,
  AgeLegend,
  WorldMap,
  Timeline,
}) {
  return (
    <>
      <LiveFilterBar
        filters={filters}
        setFilters={onSetFilters}
        options={filterOptions}
        resultCount={attacks.length}
        totalCount={data?.alerts?.length || 0}
      />
      <div className="liveMapStack">
        <WorldMap
          attacks={attacks}
          initialLoading={loading && !data}
          onExpand={onExpandMap}
        />
        <ActivityTrend attacks={attacks} onSelectBucket={onEventDrilldown} />
        <AgeLegend />
      </div>
      <EventTable
        attacks={attacks}
        activeBans={activeBans}
        selectedEvent={selectedEvent}
        onSelectEvent={onSelectEvent}
      />
      {selectedEvent && (
        <EventDetailDrawer
          event={selectedEvent}
          activeBans={activeBans}
          onClose={onCloseEvent}
          onInvestigate={onInvestigate}
        />
      )}
      {eventDrilldown && (
        <EventCollectionDrawer
          detail={eventDrilldown}
          activeBans={activeBans}
          onClose={onCloseEvent}
          onInvestigate={onInvestigate}
        />
      )}
      {mapExpanded && (
        <ExpandedMapModal
          attacks={attacks}
          error={error || data?.warning}
          selectedGroup={selectedMapGroup}
          onSelectGroup={onSelectMapGroup}
          onClose={onCloseMap}
          onInspect={onInspectMap}
          onInvestigate={onInvestigate}
          WorldMap={WorldMap}
          ActivityTrend={ActivityTrend}
          Timeline={Timeline}
        />
      )}
    </>
  );
}
