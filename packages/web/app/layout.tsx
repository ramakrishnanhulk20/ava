import type { Metadata } from "next";
import { Fraunces, Hanken_Grotesk, IBM_Plex_Mono, Instrument_Serif, Newsreader } from "next/font/google";
import { connection } from "next/server";
import type { ReactNode } from "react";
import { Grain } from "../components/Grain";
import { SmoothScroll } from "../components/SmoothScroll";
import "./globals.css";

const fraunces = Fraunces({
  subsets: ["latin"],
  style: ["normal", "italic"],
  axes: ["opsz", "SOFT", "WONK"],
  display: "swap",
  variable: "--face-fraunces",
});

// The two alternate display faces only matter once the lab picks them, so they skip the preload.
const instrument = Instrument_Serif({
  subsets: ["latin"],
  weight: "400",
  style: ["normal", "italic"],
  display: "swap",
  preload: false,
  variable: "--face-instrument",
});

const newsreader = Newsreader({
  subsets: ["latin"],
  style: ["normal", "italic"],
  axes: ["opsz"],
  display: "swap",
  preload: false,
  variable: "--face-newsreader",
});

const hanken = Hanken_Grotesk({
  subsets: ["latin"],
  display: "swap",
  variable: "--face-hanken",
});

const plex = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  display: "swap",
  variable: "--face-plex",
});

const DESCRIPTION = "A post-quantum board room on QoreChain. Board packs are sealed for today's directors, and a director who is removed is locked out of the next one.";

// Where the site lives, for the absolute address of the card image: the production host Vercel reports, or the dev server.
const HOST = process.env.VERCEL_PROJECT_PRODUCTION_URL;
const SITE = HOST !== undefined && URL.canParse(`https://${HOST}`) ? `https://${HOST}` : "http://localhost:3000";

// The card image is app/opengraph-image.png, captured from /lab/cover.
export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: "Ava",
  description: DESCRIPTION,
  openGraph: { title: "Ava", description: DESCRIPTION, siteName: "Ava", type: "website" },
  twitter: { card: "summary_large_image", title: "Ava", description: DESCRIPTION },
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Every page waits for its request, because the nonce Next stamps on its scripts is made for that one response by proxy.ts.
  // A page built ahead of time would carry no nonce, and the policy would refuse its scripts (threat model C19).
  await connection();
  const faces = [fraunces, instrument, newsreader, hanken, plex].map((face) => face.variable).join(" ");
  return (
    <html lang="en" data-serif="fraunces" data-accent="wax" className={faces} suppressHydrationWarning>
      <body>
        <SmoothScroll />
        <Grain />
        {children}
      </body>
    </html>
  );
}
