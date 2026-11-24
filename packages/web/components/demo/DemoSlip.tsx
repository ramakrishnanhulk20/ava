type DemoSlipProps = {
  /** True while the slip is on show. Its slide lives in the stylesheet, shared with the "how it works" slip. */
  on: boolean;
  /** Three lines, top to bottom. */
  rows: [string, string, string];
  place: { left: number; top: number };
};

export function DemoSlip({ on, rows, place }: DemoSlipProps) {
  return (
    <div
      data-on={on}
      className="slip paper mono absolute text-[11px] leading-[1.2] tracking-[0.12em]"
      style={{ ...place, width: 300, height: 76, padding: "10px 14px" }}
    >
      <p className="text-ink-soft">{rows[0]}</p>
      <p className="mt-2 text-ink">{rows[1]}</p>
      <p className="mt-2 text-ink-soft">{rows[2]}</p>
    </div>
  );
}
