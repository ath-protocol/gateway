import { describe, it, expect } from "vitest";
import { intersectScopes } from "../scopes.js";

describe("intersectScopes", () => {
  it("computes intersection of all three sets", () => {
    const result = intersectScopes(
      ["mail:read", "mail:send"],
      ["mail:read", "mail:send", "mail:delete"],
      ["mail:read"],
    );
    expect(result.effective).toEqual(["mail:read"]);
    expect(result.denied).toEqual([]);
  });

  it("denies scopes not approved by the agent", () => {
    const result = intersectScopes(
      ["mail:read"],
      ["mail:read", "mail:send"],
      ["mail:read", "mail:send"],
    );
    expect(result.effective).toEqual(["mail:read"]);
    expect(result.denied).toEqual(["mail:send"]);
  });

  it("denies scopes not consented by the user", () => {
    const result = intersectScopes(
      ["mail:read", "mail:send"],
      ["mail:read"],
      ["mail:read", "mail:send"],
    );
    expect(result.effective).toEqual(["mail:read"]);
    expect(result.denied).toEqual(["mail:send"]);
  });

  it("returns empty effective when no overlap", () => {
    const result = intersectScopes(
      ["mail:read"],
      ["mail:send"],
      ["mail:read", "mail:send"],
    );
    expect(result.effective).toEqual([]);
    expect(result.denied).toEqual(["mail:read", "mail:send"]);
  });

  it("handles empty arrays", () => {
    const result = intersectScopes([], [], []);
    expect(result.effective).toEqual([]);
    expect(result.denied).toEqual([]);
  });

  it("preserves full breakdown", () => {
    const result = intersectScopes(
      ["a", "b", "c"],
      ["b", "c", "d"],
      ["b", "d"],
    );
    expect(result.agent_approved).toEqual(["a", "b", "c"]);
    expect(result.user_consented).toEqual(["b", "c", "d"]);
    expect(result.requested).toEqual(["b", "d"]);
    expect(result.effective).toEqual(["b"]);
    expect(result.denied).toEqual(["d"]);
  });
});
