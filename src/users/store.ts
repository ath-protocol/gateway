/**
 * User store — in-memory storage for gateway user accounts.
 * Passwords are hashed with scrypt (Node built-in, no external deps).
 */
import crypto from "node:crypto";
import type { GatewayUser, UserRole } from "../types.js";
import { generateId } from "../utils.js";

const users = new Map<string, GatewayUser>();
const SCRYPT_KEYLEN = 64;

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString("hex");
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT_KEYLEN, (err, key) => {
      if (err) return reject(err);
      resolve(`${salt}:${key.toString("hex")}`);
    });
  });
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(":");
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT_KEYLEN, (err, key) => {
      if (err) return reject(err);
      resolve(key.toString("hex") === hash);
    });
  });
}

export function generateRandomPassword(length = 24): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  const bytes = crypto.randomBytes(length);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

export const userStore = {
  async create(username: string, password: string, role: UserRole, email?: string): Promise<GatewayUser> {
    const id = generateId("usr");
    const password_hash = await hashPassword(password);
    const user: GatewayUser = {
      id,
      username,
      email,
      password_hash,
      role,
      created_at: new Date().toISOString(),
    };
    users.set(id, user);
    return user;
  },

  async getById(id: string): Promise<GatewayUser | null> {
    return users.get(id) ?? null;
  },

  async getByUsername(username: string): Promise<GatewayUser | null> {
    for (const u of users.values()) {
      if (u.username === username) return u;
    }
    return null;
  },

  async list(): Promise<GatewayUser[]> {
    return Array.from(users.values());
  },

  async count(): Promise<number> {
    return users.size;
  },

  clear(): void {
    users.clear();
  },
};
