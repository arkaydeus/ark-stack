"""Exercise the literal front-door design examples; no deployed Ark state is used.

Requires Python 3, OpenSSL and Docker. Invoked by scripts/test-edge-config.ts.
These tests prove proxy wiring, not the future auth, observer or provider features.
"""

import base64
import hashlib
import hmac
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs/design/front-door.md"
D = Path(tempfile.mkdtemp(prefix="ark-front-door-design-"))
D.chmod(0o755)  # Proxy images run as their real unprivileged users.
PREFIX = "ark-fd-" + uuid.uuid4().hex[:12]
names = []
nets = []
TLS_PORT = 0
CADDY_IMAGE = "caddy:2.11.9@sha256:4e2425f6009577e7c651010f16679c28f7d12df3e7b1914f941a7a3370746b3c"
HAPROXY_IMAGE = "haproxy:3.2.26-alpine@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c"
PGBOUNCER_IMAGE = "edoburu/pgbouncer:v1.26.1-p0@sha256:488422e38cff912895d0d65d8963fcd306e6ac589a724398b6eb8e294e94d624"
BUN_IMAGE = "oven/bun:1.4.2@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895"
POSTGRES_IMAGE = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929"


def example(language):
    return (
        re.search(r"```" + language + r"\n(.*?)\n```", DOCUMENT.read_text(), re.S)[1]
        + "\n"
    )


for directory in ["allow", "cas", "certs"]:
    (D / directory).mkdir()
for route in ["pgbouncer", "rt_pg01", "rt_t001", "rt_p7q2"]:
    (D / "allow" / (route + ".lst")).write_text("0.0.0.0/0\n::/0\n")


def run(*a, input=None, check=True):
    r = subprocess.run(a, input=input, capture_output=True, timeout=120)
    if check and r.returncode:
        raise RuntimeError(" ".join(a[:4]) + ": " + r.stderr.decode()[-2000:])
    return (r.stdout + r.stderr).decode()


def start(name, *a):
    names.append(name)
    run("docker", "run", "-d", "--name", name, *a)


def stop(name):
    run("docker", "rm", "-f", name)
    names.remove(name)


def openssl(*a):
    run("openssl", *a)


def makecert(name, eku, san):
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(D / (name + ".key")),
        "-out",
        str(D / (name + ".csr")),
        "-subj",
        "/CN=" + name,
    )
    (D / (name + ".ext")).write_text(
        "basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nextendedKeyUsage="
        + eku
        + "\nsubjectAltName="
        + san
        + "\n"
    )
    openssl(
        "x509",
        "-req",
        "-in",
        str(D / (name + ".csr")),
        "-CA",
        str(D / "ca.pem"),
        "-CAkey",
        str(D / "ca.key"),
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        str(D / (name + ".ext")),
        "-out",
        str(D / (name + ".crt")),
    )


openssl(
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    str(D / "ca.key"),
    "-out",
    str(D / "ca.pem"),
    "-subj",
    "/CN=ReviewTestCA",
    "-days",
    "2",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
)
makecert(
    "server",
    "serverAuth",
    "DNS:mqtt.example.com,DNS:www.example.com,DNS:example.com,DNS:login.example.com,DNS:db.example.com",
)
makecert("client", "clientAuth", "DNS:client")
(D / "index").write_text("")
(D / "num").write_text("01\n")
(D / "ca.cnf").write_text(
    f"[ca]\ndefault_ca=default\n[default]\ndatabase={D}/index\nserial={D}/num\nprivate_key={D}/ca.key\ncertificate={D}/ca.pem\ndefault_md=sha256\ndefault_crl_days=2\n"
)
openssl(
    "ca", "-gencrl", "-config", str(D / "ca.cnf"), "-out", str(D / "cas/rt_p7q2.crl")
)
(D / "cas/rt_p7q2.pem").write_bytes((D / "ca.pem").read_bytes())
(D / "certs/mqtt.example.com.pem").write_bytes(
    (D / "server.crt").read_bytes() + (D / "server.key").read_bytes()
)
for host in ["www.example.com", "example.com", "login.example.com", "db.example.com"]:
    q = D / "public-certs" / host
    q.mkdir(parents=True, exist_ok=True)
    (q / "fullchain.pem").write_bytes((D / "server.crt").read_bytes())
    (q / "privkey.pem").write_bytes((D / "server.key").read_bytes())


# TLS MemoryBIO allows the initial ClientHello to be split on the wire.
def tls_connect(sni, fragment=False):
    ctx = ssl.create_default_context(cafile=str(D / "ca.pem"))
    ctx.load_cert_chain(str(D / "client.crt"), str(D / "client.key"))
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    raw = socket.create_connection(("127.0.0.1", TLS_PORT), timeout=3)
    raw.settimeout(3)
    first = True
    try:
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pass
            data = outgoing.read()
            if data:
                if first and fragment:
                    for i in range(0, len(data), 13):
                        raw.sendall(data[i : i + 13])
                        time.sleep(0.002)
                else:
                    raw.sendall(data)
                first = False
            data = raw.recv(65536)
            if not data:
                raise ConnectionError("closed during handshake")
            incoming.write(data)
        return raw, obj, incoming, outgoing
    except:
        raw.close()
        raise


def exchange(sni, payload, fragment=False):
    raw, obj, i, o = tls_connect(sni, fragment)
    try:
        obj.write(payload)
        raw.sendall(o.read())
        out = b""
        while True:
            try:
                data = obj.read(65536)
                if data:
                    out += data
                if out and not payload.startswith((b"GET ", b"POST ")):
                    if len(out) >= len(payload):
                        return out
                head, separator, body = out.partition(b"\r\n\r\n")
                length = re.search(rb"(?im)^content-length:\s*(\d+)\r?$", head)
                if separator and length and len(body) >= int(length[1]):
                    return out
                if separator and body.endswith(b"0\r\n\r\n"):
                    return out
            except ssl.SSLWantReadError:
                pass
            data = raw.recv(65536)
            if not data:
                return out
            i.write(data)
    finally:
        raw.close()


base = example("haproxy")
caddy = example("caddyfile")
(D / "Caddyfile").write_text(caddy)
try:
    (D / "haproxy.cfg").write_text(base)
    run(
        "docker",
        "run",
        "--rm",
        "--cap-drop",
        "ALL",
        "--group-add",
        "4400",
        "-v",
        str(D) + ":/usr/local/etc/haproxy:ro",
        HAPROXY_IMAGE,
        "haproxy",
        "-c",
        "-f",
        "/usr/local/etc/haproxy/haproxy.cfg",
    )
    for name, subnet in [
        (PREFIX + "-http", "100.101.102.0/24"),
        (PREFIX + "-tls", "100.88.1.0/24"),
    ]:
        run("docker", "network", "create", "--subnet", subnet, name)
        nets.append(name)
    api = 'Bun.serve({port:3000,fetch(r){const u=new URL(r.url); if(u.pathname.includes("check"))return new Response(null,{status:204});return Response.json({path:u.pathname,query:u.search,edge:r.headers.get("X-Ark-Edge-Token")})}});'
    start(
        PREFIX + "-api",
        "--network",
        PREFIX + "-http",
        "--network-alias",
        "api",
        BUN_IMAGE,
        "bun",
        "-e",
        api,
    )
    upstream = 'Bun.serve({port:3000,fetch(r){return new Response("ok",{status:302,headers:{Location:new URL(r.url).searchParams.get("to")||"/"}})}});'
    start(
        PREFIX + "-http-target",
        "--network",
        PREFIX + "-http",
        "--ip",
        "100.101.102.103",
        BUN_IMAGE,
        "bun",
        "-e",
        upstream,
    )
    start(
        PREFIX + "-caddy",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--network",
        PREFIX + "-http",
        "--network-alias",
        "edge-admin",
        "-p",
        "127.0.0.1::443",
        "-e",
        "ARK_EDGE_GATE_TOKEN=review-test-token",
        "-v",
        str(D / "Caddyfile") + ":/etc/caddy/Caddyfile:ro",
        "-v",
        str(D / "public-certs") + ":/var/lib/ark/certs:ro",
        CADDY_IMAGE,
    )
    run("docker", "network", "connect", PREFIX + "-tls", PREFIX + "-caddy")
    TLS_PORT = int(
        run("docker", "port", PREFIX + "-caddy", "443/tcp").strip().rsplit(":", 1)[1]
    )
    for mode in ["terminate_mtls", "terminate", "passthrough"]:
        code = (
            'const fs=require("node:fs");const mod=require("node:'
            + ("tls" if mode == "passthrough" else "net")
            + '");'
            + (
                'const opts={cert:fs.readFileSync("/fixtures/server.crt"),key:fs.readFileSync("/fixtures/server.key")};'
                if mode == "passthrough"
                else ""
            )
            + "mod.createServer("
            + ("opts," if mode == "passthrough" else "")
            + 's=>s.pipe(s)).listen(1883,"0.0.0.0");'
        )
        start(
            PREFIX + "-tls-target",
            "--network",
            PREFIX + "-tls",
            "--ip",
            "100.88.1.20",
            "-v",
            str(D) + ":/fixtures:ro",
            BUN_IMAGE,
            "bun",
            "-e",
            code,
        )
        for allowed in [False, True]:
            (D / "allow/rt_p7q2.lst").write_text(
                "0.0.0.0/0\n::/0\n" if allowed else "203.0.113.0/24\n"
            )
            cfg = base
            if mode == "terminate":
                cfg = cfg.replace(
                    " ca-file /usr/local/etc/haproxy/cas/rt_p7q2.pem verify required crl-file /usr/local/etc/haproxy/cas/rt_p7q2.crl",
                    "",
                )
            if mode == "passthrough":
                cfg = cfg.replace(
                    "server loop abns@rt_p7q2 send-proxy-v2",
                    "server loop 100.88.1.20:1883",
                )
            (D / "haproxy.cfg").write_text(cfg)
            start(
                PREFIX + "-hap",
                "--network",
                "container:" + PREFIX + "-caddy",
                "--cap-drop",
                "ALL",
                "--group-add",
                "4400",
                "--tmpfs",
                "/var/run/haproxy:uid=99,gid=4400,mode=0770",
                "-v",
                str(D) + ":/usr/local/etc/haproxy:ro",
                HAPROXY_IMAGE,
                "haproxy",
                "-db",
                "-f",
                "/usr/local/etc/haproxy/haproxy.cfg",
            )
            time.sleep(0.3)
            assert (
                run(
                    "docker", "inspect", "-f", "{{.State.Running}}", PREFIX + "-hap"
                ).strip()
                == "true"
            ), run("docker", "logs", PREFIX + "-hap")
            for fragmented in [False, True]:
                try:
                    result = exchange("mqtt.example.com", b"echo-test", fragmented)
                    success = result == b"echo-test"
                except (ConnectionError, OSError, ssl.SSLError) as e:
                    success = False
                    if allowed:
                        print(
                            "client error",
                            repr(e),
                            run("docker", "logs", PREFIX + "-hap", check=False),
                            run("docker", "logs", PREFIX + "-tls-target", check=False),
                        )
                assert success == allowed, (mode, allowed, fragmented, success)
            print(
                mode
                + ": "
                + ("allowed" if allowed else "outside CIDR")
                + " full/fragmented ClientHello passed",
                flush=True,
            )
            if mode == "terminate_mtls" and allowed:

                def http(path, host="www.example.com", method="GET"):
                    return exchange(
                        "www.example.com",
                        (
                            method
                            + " "
                            + path
                            + " HTTP/1.1\r\nHost: "
                            + host
                            + "\r\nConnection: close\r\n\r\n"
                        ).encode(),
                    ).decode()

                out = http("/.ark/gate/callback?code=C&state=S")
                assert (
                    '"path":"/api/gate/callback"' in out
                    and '"query":"?code=C&state=S"' in out
                ), out
                out = http("/.ark/gate/logout", method="POST")
                assert '"path":"/api/gate/logout-route"' in out, out
                for path in ["check", "users", "unexpected"]:
                    assert "404" in http("/.ark/gate/" + path).splitlines()[0]
                assert "421" in http("/", host="example.com").splitlines()[0]
                for location in [
                    "//home.tail1234.ts.net/login",
                    "//home.tail1234.ts.net./login",
                    "//100.101.102.103?x=1",
                    "http://100.101.102.103:3000",
                    "http://home.tail1234.ts.net/login",
                ]:
                    out = http("/webhooks/redirect?to=" + quote(location, safe=""))
                    loc = next(
                        x for x in out.splitlines() if x.lower().startswith("location:")
                    )
                    assert (
                        "https://www.example.com" in loc
                        and "tail1234" not in loc
                        and "100.101" not in loc
                    ), loc
                headerless = 'const t=require("node:tls").connect({host:"127.0.0.1",port:8443,rejectUnauthorized:false},()=>process.exit(9));t.on("error",()=>process.exit(0));t.setTimeout(4000,()=>process.exit(8));'
                r = subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "container:" + PREFIX + "-caddy",
                        BUN_IMAGE,
                        "bun",
                        "-e",
                        headerless,
                    ],
                    capture_output=True,
                    timeout=15,
                )
                assert r.returncode == 0, (
                    "Headerless loopback was accepted or test did not reach TLS: "
                    + r.stderr.decode()
                )
                print(
                    "Caddy: callback/query rewrite, wildcard 404, SNI/Host 421, scheme-relative redirects and required PROXY passed"
                )
            stop(PREFIX + "-hap")
        stop(PREFIX + "-tls-target")
    # Execute all existing migrations then the literal proposal on fresh and populated upgrade fixtures.
    sql_name = PREFIX + "-sql"
    start(sql_name, "-e", "POSTGRES_PASSWORD=disposable-review-only", POSTGRES_IMAGE)
    for _ in range(200):
        logs = run("docker", "logs", sql_name)
        if (
            "init process complete" in logs
            and subprocess.run(
                ["docker", "exec", sql_name, "pg_isready", "-U", "postgres"],
                capture_output=True,
            ).returncode
            == 0
        ):
            break
        time.sleep(0.1)

    def query(q, db="postgres", check=True):
        return run(
            "docker",
            "exec",
            "-i",
            sql_name,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            db,
            input=q.encode(),
            check=check,
        )

    baseline = "\n".join(
        p.read_text()
        for p in sorted((ROOT / "server/drizzle").glob("*.sql"))
        if p.name[:4] <= "0012"
    )
    for db in ["fresh", "upgrade"]:
        query("CREATE DATABASE " + db)
        query(baseline, db)
        query(
            "INSERT INTO \"user\"(id,name,email) VALUES('legacy','Legacy','legacy@example.com')",
            db,
        )
        if db == "upgrade":
            query(
                "INSERT INTO session(id,expires_at,token,user_id) VALUES('legacy-session',now()+interval '1 day','fixture-token','legacy')",
                db,
            )
        query(example("sql"), db)
        if db == "upgrade":
            assert "admin" in query("SELECT origin FROM session", db)
        rejected = query(
            "INSERT INTO session(id,expires_at,token,user_id) VALUES('missing-origin',now()+interval '1 day','missing-origin-token','legacy')",
            db,
            check=False,
        )
        assert 'null value in column "origin"' in rejected, rejected
        print(
            db + ": literal migration after 0012 and missing-origin refusal passed",
            flush=True,
        )
    stop(sql_name)

    # PgBouncer admin authority must be local-only even with a trusted application certificate.

    password = "review-admin-only"
    salt = b"disposable-review"
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096)
    b64 = lambda b: base64.b64encode(b).decode()
    secret = (
        "SCRAM-SHA-256$4096:"
        + b64(salt)
        + "$"
        + b64(hashlib.sha256(hmac.digest(salted, b"Client Key", "sha256")).digest())
        + ":"
        + b64(hmac.digest(salted, b"Server Key", "sha256"))
    )
    (D / "userlist.txt").write_text('"ark_pgbouncer_admin" "' + secret + '"\n')
    (D / "client-ca-bundle.pem").write_bytes((D / "ca.pem").read_bytes())
    (D / "pgbouncer.ini").write_text(example("ini"))
    (D / "pg_hba.conf").write_text(
        re.search(
            r"```text\n(.*?)\n```",
            DOCUMENT.read_text().split("Render this complete, ordered")[1],
            re.S,
        )[1]
        + "\n"
    )
    pgname = PREFIX + "-pgb"
    start(
        pgname,
        "--cap-drop",
        "ALL",
        "--tmpfs",
        "/var/run/pgbouncer:uid=70,gid=70,mode=0700",
        "-p",
        "127.0.0.1::5432",
        "-v",
        str(D) + ":/var/lib/ark/pgbouncer:ro",
        "-v",
        str(D / "public-certs") + ":/var/lib/ark/certs:ro",
        "--entrypoint",
        "/usr/bin/pgbouncer",
        PGBOUNCER_IMAGE,
        "/var/lib/ark/pgbouncer/pgbouncer.ini",
    )
    for _ in range(50):
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-e",
                "PGPASSWORD=" + password,
                pgname,
                "psql",
                "-h",
                "/var/run/pgbouncer",
                "-U",
                "ark_pgbouncer_admin",
                "-d",
                "pgbouncer",
                "-c",
                "SHOW VERSION",
            ],
            capture_output=True,
        )
        if result.returncode == 0:
            break
        time.sleep(0.1)
    assert result.returncode == 0, result.stderr.decode() + run(
        "docker", "logs", pgname
    )
    port = int(run("docker", "port", pgname, "5432/tcp").strip().rsplit(":", 1)[1])
    ctx = ssl.create_default_context(cafile=str(D / "ca.pem"))
    ctx.load_cert_chain(str(D / "client.crt"), str(D / "client.key"))

    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        raw.sendall(struct.pack("!II", 8, 80877103))
        assert raw.recv(1) == b"S"
        with ctx.wrap_socket(raw, server_hostname="db.example.com") as tls:
            data = b"user\0ark_pgbouncer_admin\0database\0pgbouncer\0\0"
            tls.sendall(struct.pack("!II", 8 + len(data), 196608) + data)
            response = tls.recv(8192)
            assert response[:1] == b"E" and b"login rejected" in response, response
    print(
        "Exact PgBouncer INI/HBA: local SCRAM admin accepted, TCP admin rejected with valid cert",
        flush=True,
    )
    stop(pgname)

finally:
    for name in names[::-1]:
        run("docker", "rm", "-f", name, check=False)
    for name in nets[::-1]:
        run("docker", "network", "rm", name, check=False)
    shutil.rmtree(D)
