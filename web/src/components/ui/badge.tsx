import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.08em]",
  {
    variants: {
      variant: {
        neutral: "border-border bg-muted text-muted-foreground",
        success: "border-emerald-300/40 bg-emerald-500/10 text-emerald-300",
        warning: "border-amber-300/40 bg-amber-500/10 text-amber-200",
        danger: "border-red-300/40 bg-red-500/10 text-red-200",
        info: "border-sky-300/40 bg-sky-500/10 text-sky-200",
      },
    },
    defaultVariants: { variant: "neutral" },
  },
);

export function Badge({
  className,
  variant,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export function statusVariant(status: string) {
  if (/ready|succeeded|active|running|verified|issued|uploaded/.test(status)) return "success" as const;
  if (/fail|error|denied/.test(status)) return "danger" as const;
  if (/pending|queued|await|paused|draft|provision/.test(status)) return "warning" as const;
  return "neutral" as const;
}
