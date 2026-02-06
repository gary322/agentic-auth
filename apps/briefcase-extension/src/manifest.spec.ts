import { describe, expect, it } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";

describe("extension manifest hardening", () => {
  it("uses a strict CSP and minimal permissions", async () => {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const manifestPath = path.join(__dirname, "..", "extension", "manifest.json");
    const raw = await readFile(manifestPath, "utf8");
    const manifest = JSON.parse(raw) as {
      permissions?: string[];
      content_security_policy?: { extension_pages?: string };
    };

    const perms = manifest.permissions ?? [];
    expect(perms).toContain("nativeMessaging");
    expect(perms).toContain("identity");
    expect(perms).not.toContain("storage");

    const csp = manifest.content_security_policy?.extension_pages ?? "";
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });
});

