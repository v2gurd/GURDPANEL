/**
 * GURDPANEL Gateway
 * Frontend: https://v2gurd.github.io/GURDPANEL/
 *
 * Cloudflare Worker secrets/vars:
 *
 * BPB_ORIGIN = https://kbe91pk5uqk7x-nt32homoe0n7uz.q7c7w8ng64pkc8txdimu6cksie7l1.workers.dev
 * BPB_PATH   = /EsbwC808ty68
 * SESSION_SECRET = یک رشته تصادفی طولانی
 *
 * DO NOT put BPB password or Gmail password here.
 */

const FRONTEND = "https://v2gurd.github.io";

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";

  const allowed =
    origin === FRONTEND ||
    origin === FRONTEND + "/GURDPANEL" ||
    origin.startsWith(FRONTEND + "/");

  return {
    "Access-Control-Allow-Origin": allowed ? origin : FRONTEND,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers":
      "Content-Type, X-GURD-Action, X-GURD-Path",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Vary": "Origin"
  };
}

function response(body, status = 200, request, extra = {}) {
  return new Response(body, {
    status,
    headers: {
      ...corsHeaders(request),
      ...extra
    }
  });
}

function json(data, status, request, extra = {}) {
  return response(
    JSON.stringify(data),
    status,
    request,
    {
      "Content-Type": "application/json; charset=utf-8",
      ...extra
    }
  );
}

/* ---------- crypto ---------- */

function b64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function ub64u(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";

  const bin = atob(str);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function keyFromSecret(secret) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(secret)
  );

  return crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(value, secret) {
  const key = await keyFromSecret(secret);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(value)
  );

  return `${b64u(iv)}.${b64u(new Uint8Array(encrypted))}`;
}

async function decrypt(value, secret) {
  try {
    const [ivPart, dataPart] = value.split(".");

    const key = await keyFromSecret(secret);

    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ub64u(ivPart)
      },
      key,
      ub64u(dataPart)
    );

    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

/* ---------- cookie helpers ---------- */

function parseSetCookies(headers) {
  const result = [];

  // Cloudflare Workers supports getSetCookie in newer runtime.
  if (typeof headers.getSetCookie === "function") {
    return headers.getSetCookie();
  }

  const single = headers.get("set-cookie");
  if (single) result.push(single);

  return result;
}

function cookiePairs(setCookies) {
  const map = new Map();

  for (const item of setCookies) {
    const first = item.split(";")[0];
    const eq = first.indexOf("=");

    if (eq > 0) {
      const name = first.slice(0, eq).trim();
      const value = first.slice(eq + 1).trim();

      map.set(name, value);
    }
  }

  return [...map.entries()]
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

/* ---------- BPB ---------- */

function bpbBase(env) {
  return (
    String(env.BPB_ORIGIN || "").replace(/\/+$/, "") +
    "/" +
    String(env.BPB_PATH || "").replace(/^\/+|\/+$/g, "")
  );
}

async function bpbFetch(env, path, options = {}, sessionCookies = "") {
  const url =
    bpbBase(env) +
    "/" +
    String(path || "").replace(/^\/+/, "");

  const headers = new Headers(options.headers || {});

  headers.set("User-Agent", "GURDPANEL-Gateway/1.0");

  if (sessionCookies) {
    headers.set("Cookie", sessionCookies);
  }

  return fetch(url, {
    ...options,
    headers,
    redirect: "manual"
  });
}

/* ---------- dynamic login ---------- */

function findForm(html) {
  const match = html.match(
    /<form\b[^>]*action=["']([^"']*)["'][^>]*>([\s\S]*?)<\/form>/i
  );

  if (!match) return null;

  return {
    action: match[1],
    body: match[2]
  };
}

function findInputNames(html) {
  const inputs = [];
  const re = /<input\b([^>]*)>/gi;

  let m;

  while ((m = re.exec(html))) {
    const attrs = m[1];

    const name =
      attrs.match(/\bname=["']([^"']+)["']/i)?.[1] || "";

    const type =
      attrs.match(/\btype=["']([^"']+)["']/i)?.[1] || "text";

    const placeholder =
      attrs.match(/\bplaceholder=["']([^"']+)["']/i)?.[1] || "";

    if (name) {
      inputs.push({
        name,
        type: type.toLowerCase(),
        placeholder: placeholder.toLowerCase()
      });
    }
  }

  return inputs;
}

function chooseField(inputs, password = false) {
  if (password) {
    const p = inputs.find(x => x.type === "password");
    if (p) return p.name;

    const byName = inputs.find(x =>
      /pass|password|رمز/i.test(x.name + " " + x.placeholder)
    );

    return byName?.name || "";
  }

  const email =
    inputs.find(x => x.type === "email") ||
    inputs.find(x => /email|mail|cloudflare/i.test(x.name + " " + x.placeholder));

  return email?.name || "";
}

async function login(request, env) {
  const body = await request.json().catch(() => null);

  if (!body?.email || !body?.password) {
    return json(
      { ok: false, error: "ایمیل و رمز عبور الزامی است." },
      400,
      request
    );
  }

  // Get BPB login page.
  const loginPage = await bpbFetch(env, "login", {
    method: "GET"
  });

  if (!loginPage.ok && loginPage.status !== 302) {
    return json(
      {
        ok: false,
        error: "صفحه ورود BPB در دسترس نیست.",
        status: loginPage.status
      },
      502,
      request
    );
  }

  const html = await loginPage.text();

  const form = findForm(html);

  if (!form) {
    return json(
      {
        ok: false,
        error:
          "فرم ورود BPB پیدا نشد. ساختار صفحه ورود نسخه فعلی با الگوی خودکار سازگار نیست."
      },
      502,
      request
    );
  }

  const inputs = findInputNames(form.body);

  const emailField = chooseField(inputs, false);
  const passwordField = chooseField(inputs, true);

  if (!emailField || !passwordField) {
    return json(
      {
        ok: false,
        error: "فیلدهای ورود BPB شناسایی نشدند."
      },
      502,
      request
    );
  }

  const target = new URL(form.action, loginPage.url || bpbBase(env) + "/login");

  const formData = new URLSearchParams();

  formData.set(emailField, body.email);
  formData.set(passwordField, body.password);

  // Preserve hidden fields.
  const hiddenRe =
    /<input\b([^>]*\btype=["']hidden["'][^>]*)>/gi;

  let hm;

  while ((hm = hiddenRe.exec(form.body))) {
    const attrs = hm[1];

    const name =
      attrs.match(/\bname=["']([^"']+)["']/i)?.[1];

    const value =
      attrs.match(/\bvalue=["']([^"']*)["']/i)?.[1] || "";

    if (name && !formData.has(name)) {
      formData.set(name, value);
    }
  }

  const loginResponse = await fetch(target.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": "GURDPANEL-Gateway/1.0"
    },
    body: formData,
    redirect: "manual"
  });

  const cookies = parseSetCookies(loginResponse.headers);

  if (!cookies.length) {
    const location = loginResponse.headers.get("Location") || "";

    if (
      loginResponse.status >= 300 &&
      loginResponse.status < 400 &&
      /panel/i.test(location)
    ) {
      return json(
        {
          ok: false,
          error:
            "BPB لاگین شد اما Session Cookie در پاسخ قابل دریافت نبود."
        },
        502,
        request
      );
    }

    return json(
      {
        ok: false,
        error: "ورود به BPB ناموفق بود."
      },
      401,
      request
    );
  }

  const jar = cookiePairs(cookies);

  if (!jar) {
    return json(
      { ok: false, error: "Session ایجاد نشد." },
      401,
      request
    );
  }

  const secret = env.SESSION_SECRET;

  if (!secret) {
    return json(
      {
        ok: false,
        error: "SESSION_SECRET در Worker تنظیم نشده."
      },
      500,
      request
    );
  }

  const encrypted = await encrypt(jar, secret);

  return json(
    {
      ok: true,
      message: "ورود موفق بود."
    },
    200,
    request,
    {
      "Set-Cookie":
        `GURD_SESSION=${encrypted}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=86400`
    }
  );
}

/* ---------- session ---------- */

async function getSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";

  const match = cookie.match(
    /(?:^|;\s*)GURD_SESSION=([^;]+)/
  );

  if (!match) return null;

  return decrypt(
    match[1],
    env.SESSION_SECRET
  );
}

/* ---------- generic BPB gateway ---------- */

async function gateway(request, env) {
  const session = await getSession(request, env);

  if (!session) {
    return json(
      {
        ok: false,
        authenticated: false,
        error: "ابتدا وارد GURDPANEL شوید."
      },
      401,
      request
    );
  }

  const url = new URL(request.url);

  let targetPath =
    url.searchParams.get("path") || "";

  if (!targetPath) {
    return json(
      {
        ok: false,
        error: "path مشخص نشده."
      },
      400,
      request
    );
  }

  // Security: never allow absolute URLs.
  if (
    targetPath.startsWith("http://") ||
    targetPath.startsWith("https://") ||
    targetPath.startsWith("//")
  ) {
    return json(
      {
        ok: false,
        error: "مسیر غیرمجاز."
      },
      400,
      request
    );
  }

  targetPath = targetPath.replace(/^\/+/, "");

  const upstreamHeaders = new Headers();

  const contentType = request.headers.get("Content-Type");

  if (contentType) {
    upstreamHeaders.set("Content-Type", contentType);
  }

  upstreamHeaders.set(
    "Accept",
    request.headers.get("Accept") || "*/*"
  );

  const method = request.method;

  let body = undefined;

  if (
    method !== "GET" &&
    method !== "HEAD"
  ) {
    body = await request.arrayBuffer();
  }

  const upstream = await bpbFetch(
    env,
    targetPath,
    {
      method,
      headers: upstreamHeaders,
      body
    },
    session
  );

  const responseHeaders = new Headers();

  const ct = upstream.headers.get("Content-Type");

  if (ct) {
    responseHeaders.set("Content-Type", ct);
  }

  return new Response(
    upstream.body,
    {
      status: upstream.status,
      headers: {
        ...corsHeaders(request),
        ...Object.fromEntries(responseHeaders)
      }
    }
  );
}

/* ---------- logout ---------- */

async function logout(request) {
  return json(
    {
      ok: true
    },
    200,
    request,
    {
      "Set-Cookie":
        "GURD_SESSION=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"
    }
  );
}

/* ---------- main ---------- */

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request)
      });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === "/api/login") {
        return await login(request, env);
      }

      if (url.pathname === "/api/logout") {
        return await logout(request);
      }

      if (url.pathname === "/api/gateway") {
        return await gateway(request, env);
      }

      if (url.pathname === "/api/health") {
        return json(
          {
            ok: true,
            service: "GURDPANEL",
            gateway: true
          },
          200,
          request
        );
      }

      return json(
        {
          ok: false,
          error: "Not Found"
        },
        404,
        request
      );

    } catch (error) {
      return json(
        {
          ok: false,
          error: error?.message || "Internal error"
        },
        500,
        request
      );
    }
  }
};
