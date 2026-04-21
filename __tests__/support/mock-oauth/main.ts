import { serve } from "@hono/node-server";
import { app } from "./server.js";

const port = Number(process.env.PORT ?? 4000);
serve({ fetch: app.fetch, port, hostname: "0.0.0.0" }, (info) => {
  console.log(`[mock-oauth] listening on http://0.0.0.0:${info.port}`);
});
