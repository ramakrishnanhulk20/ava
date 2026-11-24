import type { Metadata } from "next";
import { ProofPage } from "../../components/proofpage/ProofPage";

export const metadata: Metadata = {
  title: "The proof · Ava",
  description: "Four attacks on the demo board, run live from your browser against QoreChain.",
};

export default function Page() {
  return <ProofPage />;
}
