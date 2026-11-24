import { DrillBand } from "../components/drill/DrillBand";
import { Footer } from "../components/Footer";
import { Hero } from "../components/hero/Hero";
import { HowItWorks } from "../components/how/HowItWorks";
import { ProofSection } from "../components/proof/ProofSection";

export default function Home() {
  return (
    <>
      <main>
        <Hero />
        <HowItWorks />
        <ProofSection />
        <DrillBand />
      </main>
      <Footer />
    </>
  );
}
