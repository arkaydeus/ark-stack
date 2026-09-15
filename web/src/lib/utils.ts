import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(value: string | Date | null | undefined) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(value),
  );
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "include",
    headers: { "content-type": "application/json", ...init?.headers },
    ...init,
  });
  const body = (await response.json().catch(() => ({}))) as { error?: string } & T;
  if (!response.ok) throw new Error(body.error ?? "Request failed.");
  return body;
}

type ActionErrorListener = (message: string | null) => void;

let actionErrorListener: ActionErrorListener | null = null;

/** Subscribe the global banner. Passing null unsubscribes. */
export function onActionError(listener: ActionErrorListener | null) {
  actionErrorListener = listener;
}

/**
 * Runs a fire-and-forget mutation. `api` rejects on any non-2xx, and most of these calls hit
 * step-up-gated routes that answer 403 without a matching grant — dropping the rejection left
 * the button looking inert with the reason only in the console.
 */
export function act<T>(request: Promise<T>, onSuccess?: () => void | Promise<void>) {
  actionErrorListener?.(null);
  void request
    .then(() => onSuccess?.())
    .catch((error: unknown) => {
      actionErrorListener?.(error instanceof Error ? error.message : "Request failed.");
    });
}
