export function AgeLegend() {
  return (
    <div className="ageLegend" aria-label="Attack age legend">
      <span>
        <i className="ageDot ageHot" /> &lt; 15m
      </span>
      <span>
        <i className="ageDot ageWarm" /> &lt; 1h
      </span>
      <span>
        <i className="ageDot ageOld" /> &gt; 1h
      </span>
    </div>
  );
}
