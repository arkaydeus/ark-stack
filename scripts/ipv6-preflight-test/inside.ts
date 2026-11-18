import { hostPublicIpv6Addresses, ipv6ProbeRequest } from "@ark-stack/shared";

import {
  configureDockerIpv6,
  migratePublishedNetwork,
  verifyPublishedNetwork,
} from "../install-docker-ipv6.ts";
import { runIpv6Probe } from "../ipv6-preflight-probe.ts";
import { observeDockerIpv6 } from "../observe-docker-ipv6.ts";

const [operation, input] = process.argv.slice(2);
const network = {
  project: "ark-platform",
  network: "admin",
  service: "edge-ts",
  compose: ["compose", "-f", "/work/compose.yml"],
};
if (operation === "host") {
  console.log(JSON.stringify({ at: Date.now(), addresses: hostPublicIpv6Addresses() }));
} else if (operation === "observe") {
  await observeDockerIpv6("/work");
} else if (operation === "prepare") {
  await configureDockerIpv6(false);
} else if (operation === "network") {
  await migratePublishedNetwork(network);
} else if (operation === "proxy-off") {
  await verifyPublishedNetwork(network);
  await configureDockerIpv6(true);
} else if (operation === "probe" && input) {
  const { request, credentials } = JSON.parse(input);
  console.log(JSON.stringify(await runIpv6Probe(ipv6ProbeRequest.parse(request), credentials)));
} else {
  throw new Error("Unknown test guest operation.");
}
