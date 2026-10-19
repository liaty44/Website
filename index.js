require("dotenv").config();

const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const required = [
  "DATABASE_URL",
  "SESSION_SECRET",
  "GITHUB_CLIENT_ID",
  "GITHUB_CLIENT_SECRET",
  "RENDER_API_KEY",
  "RENDER_OWNER_ID"
];

for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing environment variable: ${key}`);
    process.exit(1);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    store: new pgSession({
      pool,
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

const pendingOAuth = new Map();

async function githubRequest(url, token, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || `GitHub API error ${response.status}`);
  }

  return data;
}

async function renderRequest(endpoint, method = "GET", body) {
  const response = await fetch(
    `https://api.render.com/v1${endpoint}`,
    {
      method,
      headers: {
        Authorization: `Bearer ${process.env.RENDER_API_KEY}`,
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      ...(body ? { body: JSON.stringify(body) } : {})
    }
  );

  const text = await response.text();
  let data;

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { message: text };
  }

  if (!response.ok) {
    console.error("Render API error:", response.status, data);
    throw new Error(
      data.message || `Render API error ${response.status}`
    );
  }

  return data;
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please sign in with GitHub." });
  }
  next();
}

function requireRenderService(serviceId) {
  return pool.query(
    "SELECT id FROM bots WHERE render_service_id = $1 AND user_id = $2",
    [serviceId, null]
  );
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", panel: "VorstyAFK" });
});

/* GitHub OAuth login */

app.get("/auth/github", (req, res) => {
  const state = crypto.randomBytes(24).toString("hex");

  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: process.env.GITHUB_CALLBACK_URL ||
      `${process.env.APP_URL}/auth/github/callback`,
    scope: "read:user",
    state
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

app.get("/auth/github/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state || state !== req.session.oauthState) {
      return res.status(400).send("Invalid OAuth state. Please try again.");
    }

    delete req.session.oauthState;

    const tokenResponse = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: { Accept: "application/json" },
        body: new URLSearchParams({
          client_id: process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          code: String(code),
          redirect_uri: process.env.GITHUB_CALLBACK_URL ||
            `${process.env.APP_URL}/auth/github/callback`
        })
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      throw new Error("GitHub login failed.");
    }

    const githubUser = await githubRequest(
      "https://api.github.com/user",
      tokenData.access_token
    );

    const result = await pool.query(
      `INSERT INTO users (github_id, github_username)
       VALUES ($1, $2)
       ON CONFLICT (github_id)
       DO UPDATE SET github_username = EXCLUDED.github_username
       RETURNING id, github_id, github_username`,
      [String(githubUser.id), githubUser.login]
    );

    req.session.user = result.rows[0];

    // Keep the OAuth token only for this session.
    req.session.githubToken = tokenData.access_token;

    res.redirect("/");
  } catch (error) {
    console.error("GitHub callback failed:", error.message);
    res.status(500).send("Login failed. Check your GitHub OAuth settings.");
  }
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

/* Dashboard */

app.get("/api/me", requireLogin, (req, res) => {
  res.json({
    user: {
      id: req.session.user.id,
      username: req.session.user.github_username
    }
  });
});

/* List repositories visible to the logged-in user.
   Private repositories require the appropriate GitHub authorization. */

app.get("/api/repos", requireLogin, async (req, res) => {
  try {
    const repos = await githubRequest(
      "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
      req.session.githubToken
    );

    res.json({
      repos: repos.map(repo => ({
        id: repo.id,
        name: repo.full_name,
        private: repo.private,
        branch: repo.default_branch,
        clone_url: repo.clone_url
      }))
    });
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

/* Existing bot services */

app.get("/api/bots", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, repo_name, render_service_id, created_at
       FROM bots
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.session.user.id]
    );

    res.json({ bots: result.rows });
  } catch (error) {
    res.status(500).json({ error: "Could not load bots." });
  }
});

/* Create a bot from a selected repository.
   Render service creation payloads can vary by API version/account.
   Verify the current Render API schema before enabling this in production. */

app.post("/api/bots", requireLogin, async (req, res) => {
  const { repoName, branch = "main", serviceName } = req.body || {};

  if (
    typeof repoName !== "string" ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repoName)
  ) {
    return res.status(400).json({ error: "Invalid repository name." });
  }

  if (
    typeof branch !== "string" ||
    !/^[A-Za-z0-9._/-]{1,200}$/.test(branch)
  ) {
    return res.status(400).json({ error: "Invalid branch." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Serialize creation attempts for this user so the four-bot limit
    // cannot be bypassed by simultaneous requests.
    await client.query(
      "SELECT id FROM users WHERE id = $1 FOR UPDATE",
      [req.session.user.id]
    );

    const count = await client.query(
      "SELECT COUNT(*)::int AS total FROM bots WHERE user_id = $1",
      [req.session.user.id]
    );

    if (count.rows[0].total >= 4) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "Maximum 4 bots allowed per account."
      });
    }

    // Confirm that the signed-in GitHub user can access this repository.
    const repo = await githubRequest(
      `https://api.github.com/repos/${repoName}`,
      req.session.githubToken
    );

    const owner = repo.owner.login;
    const repository = repo.name;
    const chosenBranch = branch || repo.default_branch;

    const safeName = (serviceName || `vorsty-${repository}`)
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 50);

    if (!safeName) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Invalid service name." });
    }

    // NOTE: Check the current Render API schema and your Render
    // owner's service-creation permissions before relying on this payload.
    const created = await renderRequest("/services", "POST", {
      type: "background_worker",
      name: safeName,
      ownerId: process.env.RENDER_OWNER_ID,
      repo: repo.html_url,
      branch: chosenBranch,
      autoDeploy: "yes",
      serviceDetails: {
        env: "node",
        buildCommand: "npm install",
        startCommand: "npm start",
        plan: process.env.RENDER_PLAN || "starter",
        envVars: [
          { key: "MC_HOST", value: "" },
          { key: "MC_PORT", value: "25565" },
          { key: "MC_USERNAME", value: "" },
          { key: "MC_PASSWORD", value: "" }
        ]
      }
    });

    const service = created.service || created;
    const serviceId = service.id;

    if (!serviceId) {
      throw new Error(
        "Render did not return a service ID. Check the Render API payload."
      );
    }

    const saved = await client.query(
      `INSERT INTO bots (user_id, repo_name, render_service_id)
       VALUES ($1, $2, $3)
       RETURNING id, repo_name, render_service_id, created_at`,
      [req.session.user.id, `${owner}/${repository}`, serviceId]
    );

    await client.query("COMMIT");
    res.status(201).json({ bot: saved.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Create bot failed:", error.message);
    res.status(502).json({
      error: "Could not create bot. Verify GitHub access and Render API settings."
    });
  } finally {
    client.release();
  }
});

/* Start / stop / restart / deploy / logs / environment variables */

async function getOwnedBot(req, res) {
  const result = await pool.query(
    `SELECT id, repo_name, render_service_id
     FROM bots
     WHERE id = $1 AND user_id = $2`,
    [req.params.id, req.session.user.id]
  );

  if (!result.rows.length) {
    res.status(404).json({ error: "Bot not found." });
    return null;
  }

  return result.rows[0];
}

app.post("/api/bots/:id/:action", requireLogin, async (req, res) => {
  const allowed = {
    start: "start",
    stop: "suspend",
    restart: "restart",
    deploy: "deploy"
  };

  const action = allowed[req.params.action];

  if (!action) {
    return res.status(400).json({ error: "Unsupported action." });
  }

  try {
    const bot = await getOwnedBot(req, res);
    if (!bot) return;

    const result = await renderRequest(
      `/services/${encodeURIComponent(bot.render_service_id)}/${action}`,
      "POST"
    );

    res.json({ ok: true, result });
  } catch (error) {
    console.error("Bot action failed:", error.message);
    res.status(502).json({ error: "Render action failed." });
  }
});

app.get("/api/bots/:id/logs", requireLogin, async (req, res) => {
  try {
    const bot = await getOwnedBot(req, res);
    if (!bot) return;

    const logs = await renderRequest(
      `/services/${encodeURIComponent(bot.render_service_id)}/logs`
    );

    res.json({ logs });
  } catch (error) {
    res.status(502).json({
      error: "Could not fetch logs. Verify the Render logs API endpoint."
    });
  }
});

app.get("/api/bots/:id/env", requireLogin, async (req, res) => {
  try {
    const bot = await getOwnedBot(req, res);
    if (!bot) return;

    const result = await renderRequest(
      `/services/${encodeURIComponent(bot.render_service_id)}/env-vars`
    );

    // Do not return secret values to the browser.
    const vars = Array.isArray(result) ? result : result.envVars || [];
    res.json({
      env: vars.map(item => ({
        key: item.key,
        value: ""
      }))
    });
  } catch (error) {
    res.status(502).json({
      error: "Could not fetch environment variable names."
    });
  }
});

app.put("/api/bots/:id/env", requireLogin, async (req, res) => {
  const { env } = req.body || {};

  if (
    !Array.isArray(env) ||
    env.length > 50 ||
    env.some(item =>
      !item ||
      typeof item.key !== "string" ||
      !/^[A-Z_][A-Z0-9_]*$/.test(item.key) ||
      typeof item.value !== "string" ||
      item.value.length > 5000
    )
  ) {
    return res.status(400).json({ error: "Invalid environment variables." });
  }

  try {
    const bot = await getOwnedBot(req, res);
    if (!bot) return;

    await renderRequest(
      `/services/${encodeURIComponent(bot.render_service_id)}/env-vars`,
      "PUT",
      env.map(item => ({ key: item.key, value: item.value }))
    );

    res.json({ ok: true });
  } catch (error) {
    res.status(502).json({
      error: "Could not update variables. Check the Render API schema."
    });
  }
});

/* Serve the frontend. Express 5 compatible fallback. */

app.use((req, res, next) => {
  if (req.method !== "GET" || req.path.startsWith("/api/") ||
      req.path.startsWith("/auth/")) {
    return next();
  }

  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((err, req, res, next) => {
  console.error("Server error:", err.message);
  res.status(500).json({ error: "Internal server error." });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VorstyAFK panel listening on port ${PORT}`);
});
