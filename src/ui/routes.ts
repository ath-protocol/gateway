/**
 * Web UI routes — login, dashboard, provider management, mock consent.
 */
import { Hono } from "hono";
import { html } from "hono/html";
import { agentStore } from "../registry/agent-store.js";
import { sessionStore } from "../auth/session-store.js";
import { providerStore } from "../providers/store.js";
import { loadConfig } from "../config.js";
import type { AppEnv } from "../types.js";

export const uiRoutes = new Hono<AppEnv>();

const layout = (title: string, body: string) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — ATH Gateway</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { color: #38bdf8; margin-bottom: 0.5rem; }
    h2 { color: #94a3b8; font-size: 1rem; margin-bottom: 2rem; }
    .card { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border: 1px solid #334155; }
    .card h3 { color: #f1f5f9; margin-bottom: 0.75rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge-approved { background: #064e3b; color: #6ee7b7; }
    .badge-denied { background: #7f1d1d; color: #fca5a5; }
    .badge-pending { background: #78350f; color: #fcd34d; }
    .badge-admin { background: #312e81; color: #a5b4fc; }
    .scope { display: inline-block; background: #334155; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; margin: 2px; }
    .scope-approved { border-left: 3px solid #6ee7b7; }
    .scope-denied { border-left: 3px solid #fca5a5; }
    .label { color: #94a3b8; font-size: 0.8rem; margin-bottom: 4px; }
    .success { background: #064e3b; border-color: #065f46; }
    .error { background: #7f1d1d; border-color: #991b1b; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; }
    a { color: #38bdf8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .empty { color: #64748b; font-style: italic; padding: 2rem; text-align: center; }
    input[type="text"], input[type="password"], input[type="email"] {
      width: 100%; padding: 8px 12px; background: #0f172a; border: 1px solid #334155;
      border-radius: 4px; color: #e2e8f0; font-size: 0.9rem;
    }
    .btn { border: none; padding: 8px 24px; border-radius: 4px; cursor: pointer; font-size: 1rem; }
    .btn-primary { background: #065f46; color: white; }
    .btn-danger { background: #991b1b; color: white; font-size: 0.8rem; padding: 4px 12px; }
    .btn-secondary { background: #334155; color: #e2e8f0; }
    .nav { display: flex; gap: 1rem; margin-bottom: 2rem; align-items: center; }
    .nav-right { margin-left: auto; display: flex; gap: 0.5rem; align-items: center; }
  </style>
</head>
<body>
  <div class="container">
    ${body}
  </div>
</body>
</html>`;

// GET /ui/dashboard
uiRoutes.get("/dashboard", async (c) => {
  const userId = c.get("userId") as string | undefined;
  const userRole = c.get("userRole") as string | undefined;
  const config = loadConfig();

  if (!userId) {
    return c.html(layout("Login", loginPage(config.signupEnabled)));
  }

  const isAdmin = userRole === "admin";
  const agents = await agentStore.listByTenant(userId);

  let agentCards = "";
  if (agents.length === 0) {
    agentCards = '<div class="empty">No agents registered yet. Use the ATH Client SDK to register an agent.</div>';
  } else {
    for (const agent of agents) {
      const statusBadge = `<span class="badge badge-${agent.agent_status}">${agent.agent_status}</span>`;

      let providerHtml = "";
      for (const p of agent.approved_providers) {
        const approvedScopes = p.approved_scopes.map((s) => `<span class="scope scope-approved">${s}</span>`).join("");
        const deniedScopes = p.denied_scopes.map((s) => `<span class="scope scope-denied">${s}</span>`).join("");
        providerHtml += `
          <div style="margin-top: 0.5rem;">
            <strong>${p.provider_id}</strong><br>
            ${approvedScopes ? `<div class="label">Approved:</div>${approvedScopes}` : ""}
            ${deniedScopes ? `<div class="label" style="margin-top:4px">Denied:</div>${deniedScopes}` : ""}
          </div>`;
      }

      agentCards += `
        <div class="card">
          <h3>${agent.agent_id} ${statusBadge}</h3>
          <div class="label">Client ID: ${agent.client_id}</div>
          <div class="label">Developer: ${agent.developer.name} (${agent.developer.id})</div>
          <div class="label">Purpose: ${agent.purpose}</div>
          <div class="label">Registered: ${agent.registered_at}</div>
          <div class="label">Expires: ${agent.approval_expires}</div>
          <div style="margin-top: 0.75rem;">
            <div class="label">Providers:</div>
            ${providerHtml}
          </div>
        </div>`;
    }
  }

  // Providers section (visible to all authenticated users)
  const providers = providerStore.getAll();
  const providerIds = Object.keys(providers);
  let providerSection = "";

  if (providerIds.length === 0) {
    providerSection = `
      <div class="card" style="margin-bottom: 2rem;">
        <h3>Providers</h3>
        <div class="empty">No providers configured. Running in mock mode.${isAdmin ? '<br>Use the form below or the admin API to add OAuth providers.' : ''}</div>
      </div>`;
  } else {
    let providerCards = "";
    for (const [id, p] of Object.entries(providers)) {
      const scopeTags = p.available_scopes.map((s) => `<span class="scope scope-approved">${s}</span>`).join("");
      providerCards += `
        <div class="card">
          <h3>${p.display_name} <span class="badge badge-approved">connected</span></h3>
          <div class="label">Provider ID: ${id}</div>
          <div class="label">Authorize: ${p.authorize_endpoint}</div>
          <div class="label">Token: ${p.token_endpoint}</div>
          ${p.api_base_url ? `<div class="label">API: ${p.api_base_url}</div>` : ""}
          <div class="label">Client ID: ${p.client_id}</div>
          <div style="margin-top: 0.5rem;">
            <div class="label">Available scopes (app-side authorization):</div>
            ${scopeTags || '<span class="scope">none configured</span>'}
          </div>
          ${isAdmin ? `
          <form method="POST" action="/ui/providers/delete" style="margin-top: 0.75rem;">
            <input type="hidden" name="provider_id" value="${id}">
            <button type="submit" class="btn btn-danger">Remove</button>
          </form>` : ""}
        </div>`;
    }
    providerSection = `
      <div style="margin-bottom: 2rem;">
        <h3 style="color: #94a3b8; margin-bottom: 1rem;">Providers (${providerIds.length})</h3>
        ${providerCards}
      </div>`;
  }

  // Admin-only add provider form
  const addProviderForm = isAdmin ? `
    <div class="card" id="add-provider" style="margin-bottom: 2rem;">
      <h3>Add Provider <span class="badge badge-admin">admin</span></h3>
      <p class="label" style="margin-bottom: 1rem;">Register a new OAuth 2.0 platform. Agents must be approved before they can initiate user consent.</p>
      <form method="POST" action="/ui/providers/add">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
          <div><div class="label">Provider ID</div><input type="text" name="provider_id" placeholder="github" required></div>
          <div><div class="label">Display Name</div><input type="text" name="display_name" placeholder="GitHub" required></div>
          <div><div class="label">Authorize Endpoint</div><input type="text" name="authorize_endpoint" placeholder="https://github.com/login/oauth/authorize" required></div>
          <div><div class="label">Token Endpoint</div><input type="text" name="token_endpoint" placeholder="https://github.com/login/oauth/access_token" required></div>
          <div><div class="label">API Base URL</div><input type="text" name="api_base_url" placeholder="https://api.github.com"></div>
          <div><div class="label">Available Scopes (comma-separated)</div><input type="text" name="scopes" placeholder="repo,read:user,user:email"></div>
          <div><div class="label">Client ID</div><input type="text" name="client_id" placeholder="your-oauth-client-id" required></div>
          <div><div class="label">Client Secret</div><input type="password" name="client_secret" placeholder="your-oauth-client-secret" required></div>
        </div>
        <button type="submit" class="btn btn-primary" style="margin-top: 1rem;">Add Provider</button>
      </form>
    </div>` : "";

  const roleTag = isAdmin ? '<span class="badge badge-admin">admin</span>' : "";
  const body = `
    <div class="nav">
      <h1>ATH Gateway</h1>
      <div class="nav-right">
        ${roleTag}
        <span class="label" style="margin-bottom:0">Logged in</span>
      </div>
    </div>
    <h2>Agent Trust Handshake Protocol — Trusted Handshake Gateway</h2>
    ${providerSection}
    ${addProviderForm}
    <h3 style="color: #94a3b8; margin-bottom: 1rem;">Your Registered Agents</h3>
    ${agentCards}
  `;

  return c.html(layout("Dashboard", body));
});

function loginPage(signupEnabled: boolean): string {
  return `
    <h1>ATH Gateway</h1>
    <h2>Agent Trust Handshake Protocol</h2>
    <div class="card" style="max-width:400px; margin: 2rem auto;">
      <h3>Login</h3>
      <div id="login-error" style="display:none; color: #fca5a5; margin-bottom: 1rem;"></div>
      <form id="login-form">
        <div style="margin-bottom: 0.75rem;">
          <div class="label">Username</div>
          <input type="text" name="username" id="login-username" required>
        </div>
        <div style="margin-bottom: 1rem;">
          <div class="label">Password</div>
          <input type="password" name="password" id="login-password" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%">Login</button>
      </form>
      ${signupEnabled ? `
      <div style="margin-top: 1.5rem; border-top: 1px solid #334155; padding-top: 1rem;">
        <h3>Sign Up</h3>
        <div id="signup-error" style="display:none; color: #fca5a5; margin-bottom: 1rem;"></div>
        <form id="signup-form">
          <div style="margin-bottom: 0.75rem;">
            <div class="label">Username</div>
            <input type="text" name="username" id="signup-username" required>
          </div>
          <div style="margin-bottom: 0.75rem;">
            <div class="label">Email (optional)</div>
            <input type="email" name="email" id="signup-email">
          </div>
          <div style="margin-bottom: 1rem;">
            <div class="label">Password</div>
            <input type="password" name="password" id="signup-password" required>
          </div>
          <button type="submit" class="btn btn-secondary" style="width:100%">Sign Up</button>
        </form>
      </div>` : ""}
    </div>
    <script>
      async function authRequest(url, body, errorEl) {
        errorEl.style.display = 'none';
        try {
          const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          const data = await res.json();
          if (!res.ok) { errorEl.textContent = data.message || 'Request failed'; errorEl.style.display = 'block'; return; }
          localStorage.setItem('ath_session', data.token);
          location.reload();
        } catch (e) { errorEl.textContent = 'Network error'; errorEl.style.display = 'block'; }
      }
      document.getElementById('login-form').addEventListener('submit', (e) => {
        e.preventDefault();
        authRequest('/auth/login', {
          username: document.getElementById('login-username').value,
          password: document.getElementById('login-password').value,
        }, document.getElementById('login-error'));
      });
      ${signupEnabled ? `
      document.getElementById('signup-form').addEventListener('submit', (e) => {
        e.preventDefault();
        authRequest('/auth/signup', {
          username: document.getElementById('signup-username').value,
          email: document.getElementById('signup-email').value || undefined,
          password: document.getElementById('signup-password').value,
        }, document.getElementById('signup-error'));
      });` : ""}
      // Auto-attach token for navigation
      const token = localStorage.getItem('ath_session');
      if (token) {
        document.cookie = 'ath_session=' + token + ';path=/;SameSite=Strict';
        if (!document.cookie.includes('ath_session')) location.reload();
      }
    </script>`;
}

// POST /ui/providers/add — Add a provider from dashboard form
uiRoutes.post("/providers/add", async (c) => {
  const form = await c.req.parseBody();
  const providerId = form["provider_id"] as string;
  const scopes = (form["scopes"] as string || "").split(",").map((s) => s.trim()).filter(Boolean);

  providerStore.set(providerId, {
    display_name: form["display_name"] as string,
    available_scopes: scopes,
    authorize_endpoint: form["authorize_endpoint"] as string,
    token_endpoint: form["token_endpoint"] as string,
    api_base_url: (form["api_base_url"] as string) || undefined,
    client_id: form["client_id"] as string,
    client_secret: form["client_secret"] as string,
  });

  return c.redirect("/ui/dashboard");
});

// POST /ui/providers/delete — Remove a provider from dashboard
uiRoutes.post("/providers/delete", async (c) => {
  const form = await c.req.parseBody();
  providerStore.delete(form["provider_id"] as string);
  return c.redirect("/ui/dashboard");
});

// GET /ui/callback — Post-OAuth callback landing page
uiRoutes.get("/callback", async (c) => {
  const sessionId = c.req.query("session_id");
  const success = c.req.query("success") === "true";
  const errorMsg = c.req.query("error");

  let body: string;

  if (success && sessionId) {
    body = `
      <h1>Authorization Successful</h1>
      <h2>The OAuth consent flow has been completed.</h2>
      <div class="card success">
        <h3>Session: ${sessionId}</h3>
        <p>The agent can now exchange this session for an ATH access token using <code>POST /ath/token</code>.</p>
        <p style="margin-top: 1rem;">The token's effective scopes will be the <strong>intersection</strong> of:</p>
        <ul style="margin-top: 0.5rem; padding-left: 1.5rem;">
          <li>Scopes approved for the agent (app-side authorization)</li>
          <li>Scopes the user consented to (user-side authorization)</li>
          <li>Scopes the agent requested</li>
        </ul>
      </div>
      <p style="margin-top: 1rem;"><a href="/ui/dashboard">← Back to Dashboard</a></p>
    `;
  } else {
    body = `
      <h1>Authorization Failed</h1>
      <h2>The OAuth consent flow did not complete successfully.</h2>
      <div class="card error">
        <h3>Error</h3>
        <p>${errorMsg || "Unknown error"}</p>
        ${sessionId ? `<p class="label">Session: ${sessionId}</p>` : ""}
      </div>
      <p style="margin-top: 1rem;"><a href="/ui/dashboard">← Back to Dashboard</a></p>
    `;
  }

  return c.html(layout("Authorization Result", body));
});

// GET /ui/mock-consent — Mock OAuth consent page (demo mode)
uiRoutes.get("/mock-consent", async (c) => {
  const provider = c.req.query("provider") || "unknown";
  const scopes = c.req.query("scopes")?.split(",") || [];
  const callback = c.req.query("callback") || "";
  const state = c.req.query("state") || "";

  const scopeList = scopes.map((s) => `<li>${s}</li>`).join("");

  const body = `
    <h1>Mock OAuth Consent</h1>
    <h2>This simulates a provider's OAuth consent page (mock mode)</h2>
    <div class="card">
      <h3>An agent wants to access your ${provider} account</h3>
      <p style="margin-bottom: 1rem;">The agent is requesting the following permissions:</p>
      <ul style="padding-left: 1.5rem; margin-bottom: 1.5rem;">${scopeList}</ul>
      <form action="/ui/mock-consent/approve" method="POST" style="display: inline;">
        <input type="hidden" name="callback" value="${callback}">
        <input type="hidden" name="state" value="${state}">
        <input type="hidden" name="provider" value="${provider}">
        <button type="submit" class="btn btn-primary" style="margin-right: 8px;">Approve</button>
      </form>
      <form action="/ui/mock-consent/deny" method="POST" style="display: inline;">
        <input type="hidden" name="callback" value="${callback}">
        <input type="hidden" name="state" value="${state}">
        <button type="submit" class="btn btn-danger" style="font-size: 1rem; padding: 8px 24px;">Deny</button>
      </form>
    </div>
  `;

  return c.html(layout("OAuth Consent", body));
});

// POST /ui/mock-consent/approve
uiRoutes.post("/mock-consent/approve", async (c) => {
  const formData = await c.req.parseBody();
  const callback = formData["callback"] as string;
  const state = formData["state"] as string;

  const redirectUrl = new URL(callback);
  redirectUrl.searchParams.set("code", `mock_code_${Date.now()}`);
  redirectUrl.searchParams.set("state", state);
  return c.redirect(redirectUrl.toString());
});

// POST /ui/mock-consent/deny
uiRoutes.post("/mock-consent/deny", async (c) => {
  const formData = await c.req.parseBody();
  const callback = formData["callback"] as string;
  const state = formData["state"] as string;

  const redirectUrl = new URL(callback);
  redirectUrl.searchParams.set("error", "access_denied");
  redirectUrl.searchParams.set("state", state);
  return c.redirect(redirectUrl.toString());
});
