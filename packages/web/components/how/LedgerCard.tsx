type LedgerCardProps = {
  /** True once the seal has re-formed. The fade lives in the stylesheet. */
  on: boolean;
  /** Where the card sits, in the 460px design space of the visual that holds it. */
  place: { left: number; top: number };
};

// A diagram of the idea, not data: the live before and after table is its own section.
export function LedgerCard({ on, place }: LedgerCardProps) {
  return (
    <div
      data-on={on}
      className="ledger paper mono absolute flex flex-col gap-2.5 text-[11px] tracking-[0.12em]"
      style={{ ...place, width: 240, padding: "16px 18px" }}
    >
      <p className="text-ink-soft">[ DIRECTOR C ]</p>
      <p className="flex items-center justify-between text-ink">
        <span>BEFORE REMOVAL</span>
        <span className="flex items-center gap-1.5">
          OPENED
          <svg className="text-live" width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
            <path
              d="M1.5 6.5 L4.8 9.8 L10.5 2.2"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
      </p>
      <p className="flex items-center justify-between text-ink">
        <span>AFTER REMOVAL</span>
        <span className="flex items-center gap-1.5">
          LOCKED
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
            <path d="M1 1 L9 9 M9 1 L1 9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
        </span>
      </p>
    </div>
  );
}
