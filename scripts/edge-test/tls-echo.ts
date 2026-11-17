// Test-only tailnet TLS service for `mise run test:edge` (FD-25): a TLS echo on :1883 at the simulated
// peer's 100.64.0.0/10 address. HAProxy relays it by SNI (passthrough), so the client's TLS session ends
// here, and a held session shows exactly when the edge withdrew the backend.
const tls = { cert: Bun.file("/certs/fullchain.pem"), key: Bun.file("/certs/privkey.pem") };
Bun.listen({
  hostname: "0.0.0.0",
  port: 1883,
  tls,
  socket: {
    data(socket, data) {
      socket.write(data);
    },
  },
});
console.log("edge-test TLS echo listening on :1883");
