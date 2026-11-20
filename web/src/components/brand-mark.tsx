import { cn } from "@/lib/utils";

/**
 * The Ark Stack icon beside the wordmark. Decorative (the wordmark names the product); the 96px
 * source (web/public/brand/icon-96.png, from assets/brand/ark-stack-icon.png) stays crisp up to 3x.
 */
export function BrandMark({ className }: { className?: string }) {
  return (
    <img
      src="/brand/icon-96.png"
      alt=""
      width={32}
      height={32}
      decoding="async"
      className={cn("size-8 shrink-0 select-none", className)}
      draggable={false}
    />
  );
}
