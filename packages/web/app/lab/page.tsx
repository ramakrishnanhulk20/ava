import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { LabShell, type Accent, type Serif } from "../../components/lab/LabShell";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};

const SERIFS: Serif[] = ["fraunces", "instrument", "newsreader"];
const ACCENTS: Accent[] = ["wax", "ink"];

function pick<T extends string>(value: string | string[] | undefined, allowed: T[], fallback: T): T {
  const first = Array.isArray(value) ? value[0] : value;
  return allowed.find((option) => option === first) ?? fallback;
}

// Reading the query on the server means the first paint already has the chosen face and colour.
export default async function LabPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  // The lab is a review bench for the dev server. The public site has no such page.
  if (process.env.NODE_ENV !== "development") notFound();
  const query = await searchParams;
  return (
    <LabShell initialSerif={pick(query.serif, SERIFS, "fraunces")} initialAccent={pick(query.accent, ACCENTS, "wax")} />
  );
}
