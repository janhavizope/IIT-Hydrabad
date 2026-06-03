import Link from "next/link";
import { Shield } from "lucide-react";
import { BRAND, FOOTER_LINKS } from "@/lib/constants";

export default function Footer() {
  return (
    <footer className="border-t border-white/[0.06] py-12">
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-8 px-4 sm:flex-row sm:px-6 lg:px-8">
        <div className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-primary/25 bg-primary/10 text-primary">
            <Shield className="h-4 w-4" />
          </span>
          <span className="font-semibold text-foreground">{BRAND.name}</span>
        </div>

        <nav className="flex flex-wrap justify-center gap-6">
          {FOOTER_LINKS.map((link) => (
            <Link
              key={link.label}
              href={link.href}
              className="text-sm text-muted transition hover:text-foreground"
              {...(link.href.startsWith("http") ? { target: "_blank", rel: "noopener noreferrer" } : {})}
            >
              {link.label}
            </Link>
          ))}
        </nav>

        <p className="text-xs text-muted">© {new Date().getFullYear()} APKThreatIQ. All rights reserved.</p>
      </div>
    </footer>
  );
}
