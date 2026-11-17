import { repositoryProtectionPolicy } from "@ark-stack/shared";

const xmlError = (status: number, code: string) =>
  new Response(`<Error><Code>${code}</Code></Error>`, {
    status,
    headers: { "content-type": "application/xml" },
  });

type Store = Map<string, Array<{ versionId: string; body: Uint8Array }>>;

/**
 * A tiny versioned S3 stand-in. `unsupported` lists subresources answered with 501 NotImplemented,
 * like a provider that cannot report or enforce retention.
 */
export function fakeS3(
  unsupported: string[],
  failure?: "501" | "500" | "timeout" | "bucket500",
  policy: unknown = repositoryProtectionPolicy("bkt", "ark"),
  beforeRequest?: (request: Request) => Promise<void>,
  unversioned = false,
) {
  const store: Store = new Map();
  let counter = 0;
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      await beforeRequest?.(request);
      const url = new URL(request.url);
      const [, , ...keyParts] = url.pathname.split("/");
      const key = decodeURIComponent(keyParts.join("/"));
      const sub = [...url.searchParams.keys()].find((name) => name !== "versionId") ?? "";
      if (sub && unsupported.includes(sub)) return xmlError(501, "NotImplemented");
      if (failure === "bucket500" && !key && request.method === "PUT") return xmlError(500, "InternalError");
      const destructive =
        key &&
        ((request.method === "DELETE" && url.searchParams.has("versionId")) ||
          (request.method === "PUT" && sub === "retention"));
      if (destructive && failure && failure !== "bucket500") {
        if (failure === "timeout") return new Response("timeout", { status: 504 });
        return xmlError(Number(failure), failure === "501" ? "NotImplemented" : "InternalError");
      }
      if (!key) {
        if (sub === "policy" && request.method === "GET") return Response.json(policy);
        if (sub === "versioning" && request.method === "GET") {
          return new Response("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>");
        }
        return xmlError(403, "AccessDenied");
      }
      const versions = store.get(key) ?? [];
      const versionId = url.searchParams.get("versionId");
      if (request.method === "PUT" && !sub) {
        if (unversioned && versions.length && !key.includes("/locks/")) return xmlError(403, "ObjectLocked");
        const entry = { versionId: `v${++counter}`, body: new Uint8Array(await request.arrayBuffer()) };
        store.set(key, [...versions, entry]);
        return new Response("", { headers: unversioned ? {} : { "x-amz-version-id": entry.versionId } });
      }
      if (request.method === "GET" && !sub) {
        const found = versionId ? versions.find((item) => item.versionId === versionId) : versions.at(-1);
        return found ? new Response(Buffer.from(found.body)) : xmlError(404, "NoSuchKey");
      }
      if (request.method === "DELETE") {
        if (key.includes("/locks/") && !versionId) {
          store.delete(key);
          return new Response(null, { status: 204 });
        }
        return xmlError(403, "AccessDenied");
      }
      if (sub === "retention" && request.method === "GET")
        return new Response(
          "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>",
        );
      if (sub === "retention") return xmlError(403, "AccessDenied");
      return xmlError(400, "InvalidRequest");
    },
  });
  return { server, endpoint: `http://127.0.0.1:${server.port}` };
}
