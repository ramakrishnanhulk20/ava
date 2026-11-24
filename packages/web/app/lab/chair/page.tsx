import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ChairSpike } from "../../../components/lab/ChairSpike";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};

export default function Page() {
  // A bench for the dev server only, like /lab.
  if (process.env.NODE_ENV !== "development") notFound();
  return <ChairSpike />;
}
