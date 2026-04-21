/**
 * ATH Gateway — server entry point.
 * Bootstraps root user on first start, then serves the Hono app.
 */
import { app } from "./app.js";
import { loadConfig } from "./config.js";
import { providerStore } from "./providers/store.js";
import { userStore, generateRandomPassword } from "./users/store.js";
import { serve } from "@hono/node-server";

async function bootstrap() {
  const config = loadConfig();
  const providerCount = Object.keys(providerStore.getAll()).length;

  const userCount = await userStore.count();
  if (userCount === 0) {
    const rootPassword = generateRandomPassword();
    await userStore.create("root", rootPassword, "admin");
    console.log(`\n  Root user created — username: root  password: ${rootPassword}\n`);
    console.log("  ⚠  Save this password now. It will not be shown again.\n");
  }

  console.log(`
╔══════════════════════════════════════════════════════╗
║  ATH Gateway v0.1.0                                 ║
║  Agent Trust Handshake Protocol                     ║
╠══════════════════════════════════════════════════════╣
║  Gateway URL:  ${config.gatewayUrl.padEnd(37)}║
║  OAuth mode:   ${config.oauthMode.padEnd(37)}║
║  Providers:    ${String(providerCount || "demo (mock)").padEnd(37)}║
║  Signup:       ${(config.signupEnabled ? "enabled" : "disabled").padEnd(37)}║
║  Dashboard:    ${(config.gatewayUrl + "/ui/dashboard").padEnd(37)}║
║  Discovery:    ${(config.gatewayUrl + "/.well-known/ath.json").padEnd(37)}║
╚══════════════════════════════════════════════════════╝
`);

  const server = serve(
    {
      fetch: app.fetch,
      port: config.port,
      hostname: config.host,
    },
    (info) => {
      console.log(`Listening on http://${info.address}:${info.port}`);
    },
  );

  function shutdown(signal: string) {
    console.log(`Received ${signal}, closing…`);
    server.close((err) => {
      if (err) {
        console.error(err);
        process.exit(1);
      }
      process.exit(0);
    });
  }

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

bootstrap().catch((err) => {
  console.error("Failed to start gateway:", err);
  process.exit(1);
});
