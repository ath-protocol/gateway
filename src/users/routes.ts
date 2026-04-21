/**
 * User authentication routes — signup, login, logout, whoami.
 */
import { Hono } from "hono";
import { userStore, verifyPassword } from "./store.js";
import { createSessionToken } from "./middleware.js";
import { loadConfig } from "../config.js";
import { ATHError, ATHErrorCode } from "../types.js";
import type { AppEnv } from "../types.js";

export const userRoutes = new Hono<AppEnv>();

// POST /auth/signup
userRoutes.post("/signup", async (c) => {
  const config = loadConfig();
  if (!config.signupEnabled) {
    throw new ATHError(ATHErrorCode.SIGNUP_DISABLED, "Signup is disabled", 403);
  }

  const { username, email, password } = (await c.req.json()) as {
    username: string;
    email?: string;
    password: string;
  };

  if (!username || !password) {
    throw new ATHError(ATHErrorCode.INVALID_CREDENTIALS, "username and password are required", 400);
  }

  const existing = await userStore.getByUsername(username);
  if (existing) {
    throw new ATHError(ATHErrorCode.USER_EXISTS, "Username already taken", 409);
  }

  const user = await userStore.create(username, password, "user", email);
  const token = await createSessionToken(user.id, user.role);

  return c.json({
    user: { id: user.id, username: user.username, email: user.email, role: user.role },
    token,
  }, 201);
});

// POST /auth/login
userRoutes.post("/login", async (c) => {
  const { username, password } = (await c.req.json()) as {
    username: string;
    password: string;
  };

  if (!username || !password) {
    throw new ATHError(ATHErrorCode.INVALID_CREDENTIALS, "username and password are required", 400);
  }

  const user = await userStore.getByUsername(username);
  if (!user) {
    throw new ATHError(ATHErrorCode.INVALID_CREDENTIALS, "Invalid credentials", 401);
  }

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    throw new ATHError(ATHErrorCode.INVALID_CREDENTIALS, "Invalid credentials", 401);
  }

  const token = await createSessionToken(user.id, user.role);

  return c.json({
    user: { id: user.id, username: user.username, email: user.email, role: user.role },
    token,
  });
});

// GET /auth/me — requires auth (caller applies middleware)
userRoutes.get("/me", async (c) => {
  const userId = c.get("userId") as string;
  const user = await userStore.getById(userId);
  if (!user) {
    throw new ATHError(ATHErrorCode.AUTH_REQUIRED, "User not found", 401);
  }
  return c.json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    created_at: user.created_at,
  });
});
