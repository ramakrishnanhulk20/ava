import { ML_DSA_87_SIG } from "@ava/core";
import { formatCount } from "../../lib/chain";

type SignatureSlipProps = {
  /** True while the slip is on show. Everything about its entrance and exit lives in the stylesheet. */
  on: boolean;
  /** The latest block from the chain, already formatted, or null while it is still being read. */
  block: string | null;
  /** Where the slip sits, in the 460px design space of the visual that holds it. */
  place: { left: number; top: number };
};

export function SignatureSlip({ on, block, place }: SignatureSlipProps) {
  return (
    <div
      data-on={on}
      className="slip paper mono absolute text-[11px] leading-[1.2] tracking-[0.12em]"
      style={{ ...place, width: 300, height: 76, padding: "10px 14px" }}
    >
      <p className="text-ink-soft">ML-DSA-87 SIGNATURE · {formatCount(ML_DSA_87_SIG)} BYTES</p>
      <p className="mt-2 flex items-center gap-2.5 text-ink">
        <span className="normal-case">pqcVerify</span>
        <span className="-my-[5px] h-6 w-px bg-rule" aria-hidden="true" />
        <span className="flex items-center gap-1.5 text-live">
          TRUE
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
            <path
              className="slip-tick"
              d="M1.5 6.5 L4.8 9.8 L10.5 2.2"
              pathLength={1}
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
      </p>
      <p className="mt-2 text-ink-soft">{block === null ? "READING THE CHAIN" : `BLOCK ${block}`}</p>
    </div>
  );
}
