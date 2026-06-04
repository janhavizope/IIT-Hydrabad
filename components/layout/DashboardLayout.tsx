import type { ReactNode } from "react";
import Navbar from "./Navbar";
import Sidebar from "./Sidebar";

type DashboardLayoutProps = {
  children: ReactNode;
};

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-[#030712] text-slate-100 lg:pl-72">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.16),_transparent_30%),radial-gradient(circle_at_top_right,_rgba(34,197,94,0.1),_transparent_26%),linear-gradient(180deg,_#07111f_0%,_#030712_55%,_#020409_100%)]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent"
      />

      <Sidebar />

      <div className="relative flex min-h-screen flex-col">
        <Navbar />

        <main className="flex-1 px-4 py-5 sm:px-6 lg:px-8 lg:py-8">{children}</main>
      </div>
    </div>
  );
}