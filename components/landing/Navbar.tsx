"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, Shield, Upload, X } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { BRAND, NAV_LINKS } from "@/lib/constants";
import { cn } from "@/lib/utils";

export default function Navbar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <header className="glass-nav fixed inset-x-0 top-0 z-50 h-[72px]">
      <div className="mx-auto flex h-full max-w-7xl items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
        <Link href="/" className="flex shrink-0 items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-primary/25 bg-primary/10 text-primary glow-primary">
            <Shield className="h-5 w-5" strokeWidth={2} />
          </span>
          <span className="text-lg font-semibold tracking-tight text-foreground">{BRAND.name}</span>
        </Link>

        <nav className="hidden items-center gap-1 lg:flex">
          {NAV_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={cn(
                "rounded-lg px-3.5 py-2 text-sm transition-colors",
                pathname === link.href || pathname.startsWith(`${link.href}/`)
                  ? "text-foreground"
                  : "text-muted hover:text-foreground",
              )}
            >
              {link.label}
            </Link>
          ))}
        </nav>

        <div className="hidden items-center gap-3 lg:flex">
          <Button href="/upload" variant="primary" size="sm">
            <Upload className="h-4 w-4" />
            Upload APK
          </Button>
          <Link
            href="/dashboard"
            className="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-gradient-to-br from-secondary/30 to-accent/30 text-sm font-medium text-foreground"
            aria-label="Profile"
          >
            A
          </Link>
        </div>

        <button
          type="button"
          className="flex h-10 w-10 items-center justify-center rounded-lg border border-white/10 text-foreground lg:hidden"
          onClick={() => setOpen((v) => !v)}
          aria-label="Toggle menu"
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {open ? (
        <div className="border-t border-white/10 bg-background/95 px-4 py-4 lg:hidden">
          <nav className="flex flex-col gap-1">
            {NAV_LINKS.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                onClick={() => setOpen(false)}
                className="rounded-lg px-3 py-2.5 text-sm text-muted hover:bg-white/[0.04] hover:text-foreground"
              >
                {link.label}
              </Link>
            ))}
          </nav>
          <div className="mt-4 flex flex-col gap-2">
            <Button href="/upload" variant="primary" className="w-full">
              Upload APK
            </Button>
            <Button href="/dashboard" variant="secondary" className="w-full">
              Dashboard
            </Button>
          </div>
        </div>
      ) : null}
    </header>
  );
}
