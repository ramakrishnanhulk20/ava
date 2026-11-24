import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { CoverPoster } from "../../../components/lab/CoverPoster";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};

export default function Page() {
  // A bench for the dev server only, like /lab: the cover image is captured from it.
  if (process.env.NODE_ENV !== "development") notFound();
  return <CoverPoster />;
}
