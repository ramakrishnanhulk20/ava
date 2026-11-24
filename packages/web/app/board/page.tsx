import type { Metadata } from "next";
import { BoardLobby } from "../../components/board/BoardLobby";

export const metadata: Metadata = {
  title: "Your board room · Ava",
};

export default function Page() {
  return <BoardLobby />;
}
