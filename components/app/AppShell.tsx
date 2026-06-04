import Navbar from "@/components/landing/Navbar";
import Footer from "@/components/landing/Footer";

type AppShellProps = {
  children: React.ReactNode;
  showFooter?: boolean;
};

export default function AppShell({ children, showFooter = true }: AppShellProps) {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="pt-[72px]">{children}</main>
      {showFooter ? <Footer /> : null}
    </div>
  );
}
