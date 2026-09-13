export type ExternalInventory = {
  source: "orkmail" | "pgstack" | "compose";
  domains?: string[];
  databases?: string[];
  services?: string[];
};

export function compareInventory(local: ExternalInventory, incoming: ExternalInventory) {
  const conflicts = {
    domains: (incoming.domains ?? []).filter((name) => local.domains?.includes(name)),
    databases: (incoming.databases ?? []).filter((name) => local.databases?.includes(name)),
    services: (incoming.services ?? []).filter((name) => local.services?.includes(name)),
  };
  return {
    conflicts,
    importable: {
      domains: (incoming.domains ?? []).filter((name) => !conflicts.domains.includes(name)),
      databases: (incoming.databases ?? []).filter((name) => !conflicts.databases.includes(name)),
      services: (incoming.services ?? []).filter((name) => !conflicts.services.includes(name)),
    },
    ownersImported: false,
  };
}
