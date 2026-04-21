/**
 * Authentication middleware — session JWT for gateway user accounts.
 * Sets c.set("userId") and c.set("userRole") on authenticated requests.
 */
import type { Context, Next } from "hono";
import * as jose from "jose";
import { loadConfig } from "../config.js";
import { ATHError, ATHErrorCode } from "../types.js";
import type { UserRole, AppEnv } from "../types.js";

const HEADER_PREFIX = "Bearer ";
const COOKIE_NAME = "ath_session";

/**
 * Extract the user session token. Priority:
 *  1. X-ATH-User-Token header (explicit, avoids conflict with ATH Bearer tokens)
 *  2. Cookie `ath_session`
 *  3. Authorization Bearer — but only if the value is NOT an ATH opaque token
 */
function extractToken(c: Context<AppEnv>): string | null {
  const explicit = c.req.header("X-ATH-User-Token");
  if (explicit) return explicit;
  const cookie = c.req.header("Cookie");
  if (cookie) {
    const match = cookie.split(";").map((s) => s.trim()).find((s) => s.startsWith(`${COOKIE_NAME}=`));
    if (match) return match.slice(COOKIE_NAME.length + 1);
  }
  const auth = c.req.header("Authorization");
  if (auth?.startsWith(HEADER_PREFIX)) {
    const val = auth.slice(HEADER_PREFIX.length);
    if (!val.startsWith("ath_tk_")) return val;
  }
  return null;
}

export async function createSessionToken(userId: string, role: UserRole): Promise<string> {
  const config = loadConfig();
  const secret = new TextEncoder().encode(config.jwtSecret);
  return new jose.SignJWT({ role })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(`${config.sessionTokenTtl}s`)
    .sign(secret);
}

async function verifySessionToken(token: string): Promise<{ userId: string; role: UserRole } | null> {
  try {
    const config = loadConfig();
    const secret = new TextEncoder().encode(config.jwtSecret);
    const { payload } = await jose.jwtVerify(token, secret);
    if (!payload.sub) return null;
    return { userId: payload.sub, role: (payload.role as UserRole) || "user" };
  } catch {
    return null;
  }
}

/**
 * Middleware that authenticates if a token is present but does not block.
 */
export async function optionalAuth(c: Context<AppEnv>, next: Next): Promise<void | Response> {
  const token = extractToken(c);
  if (token) {
    const session = await verifySessionToken(token);
    if (session) {
      c.set("userId", session.userId);
      c.set("userRole", session.role);
    }
  }
  await next();
}

/**
 * Middleware that requires a valid session token.
 */
export async function requireAuth(c: Context<AppEnv>, next: Next): Promise<void | Response> {
  const token = extractToken(c);
  if (!token) {
    throw new ATHError(ATHErrorCode.AUTH_REQUIRED, "Authentication required", 401);
  }
  const session = await verifySessionToken(token);
  if (!session) {
    throw new ATHError(ATHErrorCode.AUTH_REQUIRED, "Invalid or expired session", 401);
  }
  c.set("userId", session.userId);
  c.set("userRole", session.role);
  await next();
}

/**
 * Middleware that requires admin role.
 */
export async function requireAdmin(c: Context<AppEnv>, next: Next): Promise<void | Response> {
  // requireAuth is already applied before this middleware in the chain
  if (c.get("userRole") !== "admin") {
    throw new ATHError(ATHErrorCode.FORBIDDEN, "Admin access required", 403);
  }
  await next();
}
