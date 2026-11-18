import { once } from "node:events";
import { connect } from "node:tls";

import { hostPublicIpv6Addresses, ipv6ProbeRequest } from "@ark-stack/shared";

import {
  configureDockerIpv6,
  finishPublishedIpv6,
  installIpv6Observer,
  preparePublishedIpv6,
} from "../install-docker-ipv6.ts";
import { runIpv6Probe } from "../ipv6-preflight-probe.ts";
import { observeDockerIpv6 } from "../observe-docker-ipv6.ts";
import { hostCommand } from "../install-host-hardening.ts";

const [operation, input] = process.argv.slice(2);
const edge = {
  project: "ark-platform",
  network: "admin",
  service: "edge-ts",
  compose: ["compose", "-f", "/work/compose.yml"],
};
const mail = {
  project: "ark-mail",
  network: "mail-public",
  service: "stalwart",
  compose: ["compose", "-f", "/work/mail.yml"],
};
if (operation === "host") {
  console.log(JSON.stringify({ at: Date.now(), addresses: hostPublicIpv6Addresses() }));
} else if (operation === "observe") {
  await observeDockerIpv6("/work");
} else if (operation === "prepare") {
  await configureDockerIpv6(false);
} else if (operation === "upgrade-networks") {
  const restoreTailnet = await preparePublishedIpv6({
    edge,
    mail,
    hardened: true,
    tailnetRestorePath: "/work/tailnet-restore",
  });
  await hostCommand("docker", [...edge.compose, "up", "-d", "edge-ts"]);
  await hostCommand("docker", [...mail.compose, "up", "-d", "stalwart"]);
  await restoreTailnet?.();
} else if (operation === "proxy-off") {
  await finishPublishedIpv6(edge, mail);
} else if (operation === "install-observer") {
  await installIpv6Observer("/work");
} else if (operation === "postgres-handshake" && input) {
  const { address, hostname, ca } = JSON.parse(input);
  const socket = connect({
    host: address,
    port: 5432,
    servername: hostname,
    ca,
    ALPNProtocols: ["postgresql"],
  });
  socket.setTimeout(8_000, () => socket.destroy(new Error("PostgreSQL handshake timed out.")));
  try {
    await once(socket, "secureConnect");
    console.log(
      JSON.stringify({ outcome: "passed", source: socket.localAddress, sourcePort: socket.localPort }),
    );
  } finally {
    socket.destroy();
  }
} else if (operation === "probe" && input) {
  const { request, credentials } = JSON.parse(input);
  console.log(JSON.stringify(await runIpv6Probe(ipv6ProbeRequest.parse(request), credentials)));
} else {
  throw new Error("Unknown test guest operation.");
}
