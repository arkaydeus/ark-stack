// Test-only plaintext tailnet service for `mise run test:edge` (FD-14): a TCP echo on :1884 at a
// simulated peer's 100.64.0.0/10 address. Terminated TLS routes forward plaintext here over the
// tailnet, and raw TCP routes relay to it, so a held session shows exactly when the edge drained it.
Bun.listen({
  hostname: "0.0.0.0",
  port: 1884,
  socket: {
    data(socket, data) {
      socket.write(data);
    },
  },
});
console.log("edge-test TCP echo listening on :1884");
