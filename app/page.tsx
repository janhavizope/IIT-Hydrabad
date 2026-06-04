import Navbar from "@/components/landing/Navbar";
import Hero from "@/components/landing/Hero";
import Workflow from "@/components/landing/Workflow";
import Features from "@/components/landing/Features";
import AnalysisPreview from "@/components/landing/AnalysisPreview";
import ThreatMap from "@/components/landing/ThreatMap";
import Footer from "@/components/landing/Footer";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main>
        <Hero />
        <Workflow />
        <Features />
        <AnalysisPreview />
        <ThreatMap />
      </main>
      <Footer />
    </div>
  );
}
