import { cn } from "@/lib/utils";

type BadgeProps = {
  children: React.ReactNode;
  className?: string;
};

export function Badge({ children, className }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-medium tracking-wide text-primary",
        className,
      )}
    >
      {children}
    </span>
  );
}
