import Navbar from "@/components/landing/Navbar";
import Hero from "@/components/landing/Hero";
import Features from "@/components/landing/Features";
import Workflow from "@/components/landing/Workflow";
import ThreatMap from "@/components/landing/ThreatMap";
import Footer from "@/components/landing/Footer";

export default function Home() {
  return (
    <main>
      <Navbar />
      <Hero />
      <Workflow />
      <Features />
      <ThreatMap />
      <Footer />
    </main>
  );
}