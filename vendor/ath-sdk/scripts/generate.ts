#!/usr/bin/env tsx
/**
 * ATH SDK codegen — fetches schema.json + meta.json from the spec repo
 * and generates TypeScript types + Zod validators into packages/types/src/schema/.
 *
 * Usage: tsx scripts/generate.ts [--skip-download]
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_VERSION = "0.1";
const BASE_URL = `https://raw.githubusercontent.com/ath-protocol/agent-trust-handshake-protocol/refs/heads/main/schema/${SCHEMA_VERSION}`;
const OUTPUT_DIR = path.resolve(__dirname, "../packages/types/src/schema");
const LOCAL_SCHEMA = path.resolve(OUTPUT_DIR, "schema.json");
const LOCAL_META = path.resolve(OUTPUT_DIR, "meta.json");

async function download(url: string, dest: string): Promise<void> {
  console.log(`  Downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
  const text = await res.text();
  fs.writeFileSync(dest, text, "utf-8");
}

interface SchemaDef {
  description?: string;
  type?: string;
  properties?: Record<string, SchemaDef & { $ref?: string }>;
  required?: string[];
  enum?: string[];
  const?: string;
  items?: SchemaDef & { $ref?: string };
  format?: string;
  default?: unknown;
  additionalProperties?: boolean;
  minItems?: number;
  examples?: unknown[];
  $ref?: string;
}

interface Schema {
  $defs: Record<string, SchemaDef>;
}

interface Meta {
  version: string;
  endpoints: Record<string, { method: string; path: string }>;
}

function resolveRef(ref: string): string {
  return ref.replace("#/$defs/", "");
}

function toTsType(prop: SchemaDef & { $ref?: string }, defs: Record<string, SchemaDef>): string {
  if (prop.$ref) return resolveRef(prop.$ref);
  if (prop.const) return JSON.stringify(prop.const);
  if (prop.enum) return prop.enum.map((v) => JSON.stringify(v)).join(" | ");
  if (prop.type === "string") return "string";
  if (prop.type === "integer" || prop.type === "number") return "number";
  if (prop.type === "boolean") return "boolean";
  if (prop.type === "array") {
    if (prop.items) return `${toTsType(prop.items, defs)}[]`;
    return "unknown[]";
  }
  if (prop.type === "object") {
    if (prop.additionalProperties) return "Record<string, unknown>";
    return "Record<string, unknown>";
  }
  return "unknown";
}

function generateTypes(schema: Schema): string {
  const lines: string[] = [
    "// Auto-generated from ATH Protocol JSON Schema — DO NOT EDIT",
    `// Source: ${BASE_URL}/schema.json`,
    `// Generated: ${new Date().toISOString().split("T")[0]}`,
    "",
  ];

  for (const [name, def] of Object.entries(schema.$defs)) {
    if (def.description) {
      lines.push(`/** ${def.description} */`);
    }

    if (def.enum) {
      lines.push(`export type ${name} = ${def.enum.map((v) => JSON.stringify(v)).join(" | ")};`);
      lines.push("");
      continue;
    }

    if (def.type === "object" && def.properties) {
      lines.push(`export interface ${name} {`);
      const required = new Set(def.required || []);
      for (const [propName, propDef] of Object.entries(def.properties)) {
        if (propDef.description) {
          lines.push(`  /** ${propDef.description} */`);
        }
        const opt = required.has(propName) ? "" : "?";
        lines.push(`  ${propName}${opt}: ${toTsType(propDef, schema.$defs)};`);
      }
      lines.push("}");
      lines.push("");
      continue;
    }

    if (def.type === "string" && !def.enum) {
      lines.push(`export type ${name} = string;`);
      lines.push("");
      continue;
    }

    lines.push(`export type ${name} = unknown;`);
    lines.push("");
  }

  return lines.join("\n");
}

function generateZod(schema: Schema): string {
  const lines: string[] = [
    "// Auto-generated Zod validators from ATH Protocol JSON Schema — DO NOT EDIT",
    `// Source: ${BASE_URL}/schema.json`,
    `// Generated: ${new Date().toISOString().split("T")[0]}`,
    "",
    'import { z } from "zod";',
    "",
  ];

  const order = topologicalSort(schema.$defs);

  for (const name of order) {
    const def = schema.$defs[name];

    if (def.enum) {
      lines.push(`export const z${name} = z.enum([${def.enum.map((v) => JSON.stringify(v)).join(", ")}]);`);
      lines.push("");
      continue;
    }

    if (def.type === "object" && def.properties) {
      const required = new Set(def.required || []);
      const fields: string[] = [];
      for (const [propName, propDef] of Object.entries(def.properties)) {
        let zodType = toZodType(propDef, schema.$defs);
        if (!required.has(propName)) zodType += ".optional()";
        fields.push(`  ${propName}: ${zodType},`);
      }
      lines.push(`export const z${name} = z.object({`);
      lines.push(...fields);
      lines.push("});");
      lines.push("");
      continue;
    }

    if (def.type === "string") {
      lines.push(`export const z${name} = z.string();`);
      lines.push("");
      continue;
    }

    lines.push(`export const z${name} = z.unknown();`);
    lines.push("");
  }

  return lines.join("\n");
}

function toZodType(prop: SchemaDef & { $ref?: string }, defs: Record<string, SchemaDef>): string {
  if (prop.$ref) return `z${resolveRef(prop.$ref)}`;
  if (prop.const) return `z.literal(${JSON.stringify(prop.const)})`;
  if (prop.enum) return `z.enum([${prop.enum.map((v) => JSON.stringify(v)).join(", ")}])`;
  if (prop.type === "string") {
    if (prop.format === "uri") return "z.string().url()";
    if (prop.format === "email") return "z.string().email()";
    if (prop.format === "date-time") return "z.string().datetime()";
    return "z.string()";
  }
  if (prop.type === "integer") return "z.number().int()";
  if (prop.type === "number") return "z.number()";
  if (prop.type === "boolean") return "z.boolean()";
  if (prop.type === "array") {
    if (prop.items) {
      const itemType = toZodType(prop.items, defs);
      return `z.array(${itemType})`;
    }
    return "z.array(z.unknown())";
  }
  if (prop.type === "object") {
    return "z.record(z.string(), z.unknown())";
  }
  return "z.unknown()";
}

function topologicalSort(defs: Record<string, SchemaDef>): string[] {
  const visited = new Set<string>();
  const result: string[] = [];

  function visit(name: string) {
    if (visited.has(name)) return;
    visited.add(name);
    const def = defs[name];
    if (!def) return;
    const refs = extractRefs(def);
    for (const ref of refs) visit(ref);
    result.push(name);
  }

  for (const name of Object.keys(defs)) visit(name);
  return result;
}

function extractRefs(obj: unknown): string[] {
  const refs: string[] = [];
  if (typeof obj !== "object" || obj === null) return refs;
  for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
    if (key === "$ref" && typeof val === "string") {
      refs.push(resolveRef(val));
    } else {
      refs.push(...extractRefs(val));
    }
  }
  return refs;
}

function generateIndex(meta: Meta): string {
  const lines: string[] = [
    "// Auto-generated barrel — DO NOT EDIT",
    "",
    'export * from "./types.gen.js";',
    'export { ',
  ];

  const zodExports: string[] = [];
  const schemaDefs = JSON.parse(fs.readFileSync(LOCAL_SCHEMA, "utf-8")) as Schema;
  for (const name of Object.keys(schemaDefs.$defs)) {
    zodExports.push(`  z${name}`);
  }
  lines.push(...zodExports.map((e, i) => e + (i < zodExports.length - 1 ? "," : "")));
  lines.push('} from "./zod.gen.js";');
  lines.push("");
  lines.push(`export const PROTOCOL_VERSION = ${JSON.stringify(meta.version)};`);
  lines.push("");
  lines.push("export const ATH_ENDPOINTS = {");
  for (const [name, ep] of Object.entries(meta.endpoints)) {
    lines.push(`  ${name}: { method: ${JSON.stringify(ep.method)}, path: ${JSON.stringify(ep.path)} },`);
  }
  lines.push("} as const;");
  lines.push("");

  return lines.join("\n");
}

async function main() {
  const skipDownload = process.argv.includes("--skip-download");
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  if (!skipDownload) {
    console.log("Downloading ATH schema files...");
    await download(`${BASE_URL}/schema.json`, LOCAL_SCHEMA);
    await download(`${BASE_URL}/meta.json`, LOCAL_META);
    console.log("Download complete.\n");
  }

  const schema = JSON.parse(fs.readFileSync(LOCAL_SCHEMA, "utf-8")) as Schema;
  const meta = JSON.parse(fs.readFileSync(LOCAL_META, "utf-8")) as Meta;

  console.log("Generating TypeScript types...");
  fs.writeFileSync(path.join(OUTPUT_DIR, "types.gen.ts"), generateTypes(schema));

  console.log("Generating Zod validators...");
  fs.writeFileSync(path.join(OUTPUT_DIR, "zod.gen.ts"), generateZod(schema));

  console.log("Generating index barrel...");
  fs.writeFileSync(path.join(OUTPUT_DIR, "index.ts"), generateIndex(meta));

  console.log("\nDone! Generated files in packages/types/src/schema/");
}

main().catch((err) => {
  console.error("Generate failed:", err);
  process.exit(1);
});
