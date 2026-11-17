import { prepareEdgeUpgrade } from "./install-edge-l4.ts";

await prepareEdgeUpgrade({
  l4Root: process.env.ARK_EDGE_L4_DIR ?? "/usr/local/etc/haproxy",
  edgeRoot: process.env.ARK_EDGE_DIR ?? "/var/lib/ark/edge",
  uid: Number(process.env.ARK_CONTAINER_UID ?? "1000"),
  gid: Number(process.env.ARK_CONTAINER_GID ?? "1000"),
});
