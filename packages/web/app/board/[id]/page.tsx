import type { Metadata } from "next";
import { BoardRoom } from "../../../components/board/BoardRoom";

export const metadata: Metadata = {
  title: "Board room · Ava",
};

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <BoardRoom id={id} />;
}
