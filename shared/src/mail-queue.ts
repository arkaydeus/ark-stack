export type MailQueueItem = {
  id: string;
  recipient: string;
  sender: string;
  ageSeconds: number;
  state: "deferred" | "queued" | "bounce";
};

export function canMutateQueue(input: {
  action: "retry" | "delete";
  item: MailQueueItem;
  localDomains: string[];
}) {
  const domain = input.item.recipient.split("@")[1] ?? "";
  if (!input.localDomains.includes(domain)) {
    return { ok: false, reason: "Queue mutations are limited to local recipients." };
  }
  if (input.action === "delete" && input.item.state === "queued" && input.item.ageSeconds < 60) {
    return { ok: false, reason: "Refuse to delete a message that is still in its first retry window." };
  }
  return { ok: true };
}

export function redactQueueItem(item: MailQueueItem) {
  return {
    id: item.id,
    recipient: item.recipient,
    sender: item.sender,
    ageSeconds: item.ageSeconds,
    state: item.state,
  };
}

export function parseStalwartQueue(text: string): MailQueueItem[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      try {
        const row = JSON.parse(line) as Partial<MailQueueItem>;
        if (!row.id || !row.recipient) return [];
        return [
          {
            id: String(row.id),
            recipient: String(row.recipient),
            sender: String(row.sender ?? ""),
            ageSeconds: Number(row.ageSeconds ?? 0),
            state: row.state === "bounce" || row.state === "deferred" ? row.state : "queued",
          },
        ];
      } catch {
        return [];
      }
    });
}
