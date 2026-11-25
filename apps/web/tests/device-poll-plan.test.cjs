const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
const routePath = path.join(
  webDir,
  "src/app/api/v1/auth/device/poll/route.ts",
);
const planPath = path.join(webDir, "src/lib/plan.ts");

function transpileModule(filePath, localRequire, DateClass = Date) {
  const output = ts.transpileModule(fs.readFileSync(filePath, "utf8"), {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const fn = new Function(
    "exports",
    "require",
    "module",
    "__filename",
    "__dirname",
    "Date",
    output,
  );
  fn(module.exports, localRequire, module, filePath, path.dirname(filePath), DateClass);
  return module.exports;
}

function loadPlanModule(DateClass = Date) {
  return transpileModule(planPath, require, DateClass);
}

function createServiceClient(user, tokenOverrides = {}) {
  const calls = [];
  const token = {
    id: "device-token-1",
    user_id: "user-1",
    status: "approved",
    expires_at: "2099-01-01T00:00:00.000Z",
    device_expires_at: "2099-01-01T00:00:00.000Z",
    token_hash: null,
    ...tokenOverrides,
  };

  return {
    calls,
    token,
    from(table) {
      const query = { table, columns: null, update: null };
      const builder = {
        select(columns) {
          query.columns = columns;
          calls.push({ ...query });
          return this;
        },
        update(values) {
          query.update = values;
          return this;
        },
        eq() {
          return this;
        },
        is() {
          return this;
        },
        async single() {
          return { data: table === "device_tokens" ? token : user };
        },
        async maybeSingle() {
          return {
            data: query.update ? { id: token.id } : table === "device_tokens" ? token : user,
            error: null,
          };
        },
        then(resolve, reject) {
          calls.push({ ...query });
          return Promise.resolve({ error: null }).then(resolve, reject);
        },
      };
      return builder;
    },
  };
}

function loadRoute(serviceClient, DateClass = Date) {
  const localRequire = (specifier) => {
    if (specifier === "@/lib/commissioning") {
      return { requireHostedService: () => null };
    }
    if (specifier === "@/lib/supabase-server") {
      return { createServiceClient: () => serviceClient };
    }
    if (specifier === "@/lib/http-body") {
      return {
        readBoundedJsonObject: async (request) => request.json(),
        requestBodyErrorResponse: () =>
          Response.json({ error: "invalid request body" }, { status: 400 }),
      };
    }
    if (specifier === "@/lib/plan") return loadPlanModule(DateClass);
    if (specifier === "crypto") return crypto;
    return require(specifier);
  };
  return transpileModule(routePath, localRequire, DateClass);
}

test("pending device authorization can be polled at the advertised five-second interval", async () => {
  let now = Date.parse("2026-01-01T00:00:00.000Z");
  class Clock extends Date {
    constructor(...args) {
      super(...(args.length ? args : [now]));
    }
    static now() { return now; }
  }
  const serviceClient = createServiceClient(null, { status: "pending" });
  const { POST } = loadRoute(serviceClient, Clock);
  const poll = () => POST(new Request("https://phm.dev/api/v1/auth/device/poll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ device_code: "device-code-1" }),
  }));

  const first = await poll();
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { status: "pending" });
  now += 5_000; // The initiation endpoint advertises an interval of five seconds.
  const second = await poll();
  assert.equal(second.status, 200);
  assert.deepEqual(await second.json(), { status: "pending" });
  now += 5_500; // A fractional number of seconds is also a valid elapsed interval.
  const third = await poll();
  assert.equal(third.status, 200);
  assert.deepEqual(await third.json(), { status: "pending" });
  assert.equal(serviceClient.calls.filter(({ table }) => table === "device_tokens").length, 3);
  assert.ok(!serviceClient.calls.some(({ table }) => table === "users"));
});

test("polling falls back to the legacy expiry when device expiry is missing", async () => {
  let now = Date.parse("2026-01-01T00:00:00.000Z");
  class Clock extends Date {
    constructor(...args) {
      super(...(args.length ? args : [now]));
    }
    static now() { return now; }
  }
  const serviceClient = createServiceClient(null, {
    status: "pending",
    device_expires_at: null,
    expires_at: "2026-01-01T00:00:04.000Z",
  });
  const { POST } = loadRoute(serviceClient, Clock);
  const poll = () => POST(new Request("https://phm.dev/api/v1/auth/device/poll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ device_code: "device-code-1" }),
  }));

  const first = await poll();
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { status: "pending" });
  now += 5_000;
  const second = await poll();
  assert.equal(second.status, 200);
  assert.deepEqual(await second.json(), { status: "expired" });
  assert.ok(!serviceClient.calls.some(({ table }) => table === "users"));
});

test("a pending device window remains usable while time remains", async () => {
  let now = Date.parse("2026-01-01T00:00:00.000Z");
  class Clock extends Date {
    constructor(...args) {
      super(...(args.length ? args : [now]));
    }
    static now() { return now; }
  }
  const serviceClient = createServiceClient(null, {
    status: "pending",
    device_expires_at: "2026-01-01T00:00:06.000Z",
    expires_at: "2026-01-01T00:00:01.000Z",
  });
  const { POST } = loadRoute(serviceClient, Clock);
  const poll = () => POST(new Request("https://phm.dev/api/v1/auth/device/poll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ device_code: "device-code-1" }),
  }));

  assert.deepEqual(await (await poll()).json(), { status: "pending" });
  now += 5_000; // One second remains after the advertised interval.
  assert.deepEqual(await (await poll()).json(), { status: "pending" });
  now += 1_001;
  assert.deepEqual(await (await poll()).json(), { status: "expired" });
  assert.ok(!serviceClient.calls.some(({ table }) => table === "users"));
});

test("device poll selects expiry and returns only the normalized plan", async () => {
  const serviceClient = createServiceClient({
    github_login: "octocat",
    email: "octo@example.com",
    plan: "pro",
    plan_expires_at: "not-a-date",
  });
  const { POST } = loadRoute(serviceClient);

  const response = await POST(
    new Request("https://phm.dev/api/v1/auth/device/poll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: "device-code-1" }),
    }),
  );

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.status, "approved");
  assert.equal(typeof body.access_token, "string");
  assert.equal(body.access_token.length, 128);
  assert.deepEqual(body.user, {
    github_login: "octocat",
    email: "octo@example.com",
    plan: "free",
  });
  assert.ok(
    serviceClient.calls.some(
      ({ table, columns }) =>
        table === "users" &&
        columns === "github_login, email, plan, plan_expires_at",
    ),
  );
});

for (const [elapsedMs, expectedPlan] of [[4_999, "pro"], [5_000, "free"], [5_001, "free"]]) {
  test(`approval after ${elapsedMs}ms of polling returns the current ${expectedPlan} plan`, async () => {
    let now = Date.parse("2026-01-01T00:00:00.000Z");
    class Clock extends Date {
      constructor(...args) {
        super(...(args.length ? args : [now]));
      }
      static now() { return now; }
    }
    const serviceClient = createServiceClient({
      github_login: "octocat",
      email: "octo@example.com",
      plan: "pro",
      plan_expires_at: "2026-01-01T00:00:05.000Z",
    }, { status: "pending" });
    const { POST } = loadRoute(serviceClient, Clock);
    const poll = () => POST(new Request("https://phm.dev/api/v1/auth/device/poll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: "device-code-1" }),
    }));

    assert.deepEqual(await (await poll()).json(), { status: "pending" });
    assert.ok(!serviceClient.calls.some(({ table }) => table === "users"));
    now += elapsedMs;
    serviceClient.token.status = "approved";
    const response = await poll();
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.status, "approved");
    // effectivePlan documents expired plans as free, including the exact deadline.
    assert.deepEqual(body.user, {
      github_login: "octocat",
      email: "octo@example.com",
      plan: expectedPlan,
    });
  });
}

for (const status of ["pending", "approved"]) {
  test(`an elapsed fifteen-minute polling window expires even when ${status}`, async () => {
    let now = Date.parse("2026-01-01T00:00:00.000Z");
    class Clock extends Date {
      constructor(...args) {
        super(...(args.length ? args : [now]));
      }
      static now() { return now; }
    }
    const serviceClient = createServiceClient(null, {
      status: "pending",
      // The initiation endpoint advertises expires_in: 900 and interval: 5.
      device_expires_at: "2026-01-01T00:15:00.000Z",
    });
    const { POST } = loadRoute(serviceClient, Clock);
    const poll = () => POST(new Request("https://phm.dev/api/v1/auth/device/poll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: "device-code-1" }),
    }));

    for (let elapsed = 0; elapsed < 900_000; elapsed += 5_000) {
      const response = await poll();
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { status: "pending" });
      now += 5_000;
    }
    now += 1; // Past the deadline, without real timers or network requests.
    serviceClient.token.status = status;
    for (let retry = 0; retry < 2; retry++) {
      const response = await poll();
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { status: "expired" });
      now += 5_000;
    }
    assert.ok(serviceClient.calls.some(({ update }) => update?.status === "expired"));
    assert.ok(!serviceClient.calls.some(({ table }) => table === "users"));
    assert.ok(!serviceClient.calls.some(({ update }) => update && "token_hash" in update));
  });
}

test("device poll on an already expired window reports expired and issues nothing", async () => {
  const calls = [];
  const expiredToken = {
    id: "device-token-expired",
    user_id: "user-1",
    status: "approved",
    expires_at: "2000-01-01T00:00:00.000Z",
    device_expires_at: "2000-01-01T00:00:00.000Z",
    token_hash: null,
  };
  const serviceClient = {
    from(table) {
      const query = { table, update: null, select: null };
      const builder = {
        select(columns) {
          query.select = columns;
          return this;
        },
        update(values) {
          query.update = values;
          return this;
        },
        eq() {
          return this;
        },
        is() {
          return this;
        },
        async maybeSingle() {
          calls.push({ ...query });
          return { data: table === "device_tokens" ? expiredToken : null, error: null };
        },
        // Awaiting the builder directly resolves a bare update().eq().
        then(resolve) {
          calls.push({ ...query });
          resolve({ error: null });
        },
      };
      return builder;
    },
  };
  const { POST } = loadRoute(serviceClient);

  const poll = () =>
    POST(
      new Request("https://phm.dev/api/v1/auth/device/poll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ device_code: "device-code-expired" }),
      }),
    );

  for (let i = 0; i < 2; i++) {
    const response = await poll();
    assert.equal(response.status, 200);
    const body = await response.json();
    // "expired" tells the CLI to stop polling; nothing else is returned.
    assert.deepEqual(body, { status: "expired" });
  }

  assert.ok(
    calls.some(({ table, update }) => table === "device_tokens" && update?.status === "expired"),
  );
  assert.ok(!calls.some(({ table }) => table === "users"));
  assert.ok(!calls.some(({ update }) => update && "token_hash" in update));
});
