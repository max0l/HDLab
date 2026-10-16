# HDLab security review

Date: 16 October 2026

Scope: targeted source review of request validation, authentication, simulation execution, artifact processing, and SVG delivery; isolated worker-function, input-coercion, rendering, and Mongoose query-casting tests; local authentication, concurrency, and quota checks using actual handlers/services with mocked dependencies; a local Chromium SVG/Blob execution test; a user-reported live query-selector PoC; public advisories matched against the supplied kernel string. This is not a complete audit. Running containers, effective host security policies, and livepatch state could not be inspected. No container escape was attempted or demonstrated.

## User execution capabilities

The current simulation flow permits general-purpose code execution inside the job container, beyond HDL evaluation:

- SystemVerilog `$system` calls can invoke shell commands.
- Submitted Cocotb Python can execute Python code, launch available programs, and access operating-system interfaces.
- A submitted `sim_main.cpp` is accepted, compiled, and executed, allowing native C++ code.

Within the container's permissions and resource limits, users can inspect the environment, read accessible files, write or replace job artifacts, create processes, and attempt kernel exploitation. Commands such as `uname -a` can disclose the shared kernel version and architecture; `/etc/os-release` identifies the container distribution. The container hostname does not normally identify the host machine. Installed shells, Python, and compiler tools also provide means to perform actions without downloading additional software.

These capabilities are established by the execution path; they do not demonstrate a successful container escape. The security boundary is the container and its host protections, rather than a restriction to safe HDL or Python statements. Blocking `$system` alone would leave Python and C++ execution available.

## Findings

### 1. Malformed source can block the worker before sandbox execution

**Confirmed in an isolated function test.** `stripComments()` in `apps/worker/src/svSources.js` uses a regular expression that repeatedly scans unterminated block comments. Testing the actual `orderSvSources()` function with repeated unterminated comment markers took approximately 33 ms for 30 KB and 772 ms for 150 KB; a 600 KB case exceeded three seconds and was terminated.

Source preparation runs synchronously in the worker before the simulation container starts. It can block processing of other jobs and delay the worker's container-kill timers. The API permits requests up to 12 MB and does not impose a separate project source-file size limit.

**Remediation:** replace comment stripping with a linear-time parser and isolate or bound source preprocessing independently of the simulation timeout.

### 2. A named-pipe result file can block artifact collection

**Confirmed in an isolated function test.** `readJobFile()` in `apps/worker/src/sandbox.js` opens an output file before checking whether it is a regular file. A named pipe at `sim.log` passed the path checks and blocked the open operation until the test process was terminated.

Submitted Python or native code can create such a file in its writable job directory. Result collection happens after execution, outside the container timeout. Repeated blocked operations could exhaust the worker's filesystem thread pool.

**Remediation:** open outputs without blocking, retain symlink protections, and reject nonregular files before reading.

### 3. Job storage and simulation logs lack explicit total bounds

**Configuration finding.** `sandbox.js` limits each file to 256 MB by default, but configures no total job disk quota or file-count limit. The container root filesystem is writable. Creating many files can consume shared host storage.

Simulation containers are launched through `docker run` and do not inherit Compose's log rotation settings. The worker's 64 KB output-forwarding cap does not limit Docker's own logs. Actual log retention depends on daemon settings, which were not inspected. Docker documents disk exhaustion with its default unrotated logging configuration.

**Remediation:** enforce total storage/inode quotas and explicit simulation-container log limits; use a read-only root filesystem with bounded writable storage where compatible.

### 4. Supplied kernel predates a relevant container-escape fix

**Advisory match, not an exploit test.** The supplied kernel was `6.8.0-134-generic #134-Ubuntu`. Assuming a standard Ubuntu build without additional patches:

| CVE | Published status relevant to this build |
| --- | --- |
| [CVE-2026-52910](https://ubuntu.com/security/CVE-2026-52910) | Noble fix: `6.8.0-146.146`, newer than the supplied build. |
| [CVE-2026-80521](https://ubuntu.com/security/CVE-2026-80521) | Noble `linux` listed as vulnerable, with work in progress when checked. |
| [CVE-2026-31431](https://ubuntu.com/security/CVE-2026-31431), Copy Fail | Noble fix: `6.8.0-117.117`; the supplied standard build should include it. |

[Original research](https://depthfirst.com/research/containers-are-no-longer-safe) reports container escapes using the first CVE on Ubuntu 24.04 and the second on Ubuntu 26.04. Exploitability under HDLab's exact restrictions remains unverified. Updating the container image does not update the shared host kernel.

**Remediation:** patch and reboot the execution host, verify outstanding CVE status and effective runtime policies, and separate hostile execution from application/database infrastructure.

### 5. Object-valued project IDs allow query-selector injection

**Confirmed by isolated query casting and a user-reported live endpoint test.** `POST /api/simulations` passes `req.body.projectId` directly to `Project.findById()` in `apps/backend/src/routes.js:229`. With the locked Mongoose 8.24.5 dependency, an object such as `{"$ne":null}` becomes the filter `{"_id":{"$ne":null}}`, rather than being rejected as an invalid identifier.

The live PoC used `{"projectId":{"$in":["<owned-project-id>"]},"testbenchType":"systemverilog"}`. The user reported a successful response creating a simulation for that project. The authenticated caller can therefore change an intended equality lookup into an operator-based query. The subsequent ownership check remains effective in the reviewed path; no cross-user access, authentication bypass, or RCE was demonstrated. Current demonstrated impact is limited.

The reproduction script and instructions are in `apps/backend/scripts/poc-query-selector.mjs` and `apps/backend/scripts/poc-query-selector.md`. Offline mode performs no database operations; HTTP mode creates one simulation restricted to an existing project owned by the caller.

**Remediation:** require a 24-character hexadecimal string before querying, and include the authenticated owner in the project lookup. Preserve ownership enforcement. The endpoint should reject operator objects with HTTP 400.

### 6. Other input-validation and result-trust gaps

These findings have different consequences; acceptance of an object does not always imply database injection.

| Input / location | Evidence and impact |
| --- | --- |
| `settings.generateWave` / `settings.generateNetlist`, `services/simulations.js:71` | Isolated execution of the actual sanitizer confirmed that the string `"false"` and an operator-shaped object enable the corresponding option. Values are converted to booleans, so this is unexpected processing rather than MongoDB injection. |
| `isCompleted`, `routes/tutorial.js:109` | Uses `!!isCompleted`; objects and `"false"` become `true`. Coercion was verified locally. The update is scoped to the caller's own progress. |
| `files[].content`, `services/simulations.js:42` | Requires strings but imposes no individual file-size limit within the 12 MB request limit. This permits large malformed inputs relevant to finding 1. |
| Project/simulation URL IDs, `routes.js` | Lack explicit hexadecimal-format checks before Mongoose queries. Some routes return casting errors as HTTP 500 with internal error details. These parameters are strings, so this is not the object-based injection demonstrated in finding 5. Source review only. |
| OAuth `profile.id`, `profile.username`, `profile.email`, `routes/oauth.js:165` | Only truthiness is checked before profile processing and queries. The response comes from the configured GitLab server, not directly from an ordinary HTTP client. This is an external-data validation gap; no user-controlled OAuth injection was demonstrated. |

Tutorial completion also has a separate trust limitation: the progress endpoint accepts the caller's `validationStatus: "passed"`, and `/tutorial/validate` accepts a user-supplied testbench and determines success from simulation log text. These records cannot establish independently verified correctness. This is material if used for grading; self-reported progress may be appropriate for personal practice. This conclusion is based on source review, not an end-to-end forged-result test.

**Remediation:** require actual booleans, bound source sizes, validate ID formats, validate the types and lengths of OAuth profile fields, and return controlled client errors. If authoritative assessment is required, use trusted testbenches and independently verified results. No second direct HTTP-to-MongoDB operator injection was confirmed in the reviewed routes.

### 7. Generated SVG can contain injected script markup

**Confirmed in the rendering pipeline and a local Chromium test; source fix applied.** `netlistsvg` 1.0.2 serializes user-controlled names and labels without XML escaping. A crafted cell type survived `prepareNetlist()` as an actual SVG `<script>` element; a quoted port name also introduced event-handler attributes. Submitted Python/native code can replace the job's `netlist.json`, so renderer input cannot be assumed to be trustworthy Yosys output.

The normal `<img>` preview does not execute SVG scripts, and the API's attachment/CSP headers protect direct responses. However, `apps/frontend/src/hooks/useSimArtifacts.js` rebuilds SVG as a Blob URL. Opening that Blob URL as a document changes its execution context and does not retain the API response headers. A local Chromium harness reproduced script execution on document navigation using the application's generated SVG and the configured page policy, which has no `script-src` restriction. This requires opening the artifact as a document; automatic execution in the image preview and cross-account delivery were not demonstrated.

**PoC:** `poc/svg-xss/upload_me.py` is an uploadable cocotb testbench that overwrites the job's `netlist.json` from inside the sandbox (the container's working directory is the job directory, `sandbox.js`), planting a cell whose type is a `<script>` payload. The job succeeds, and the stored SVG artifact contains the live script element. Execution is demonstrated in the screen recording `poc/svg-xss/poc.webm`: opening the schematic's Blob URL as a document (same browser session, e.g. `window.open(img.src)` from the schematic view) runs the payload in the application origin, flipping the tab title to `XSS-EXECUTED` and drawing a marker into the document. The `<img>` preview remains inert.

**Fix:** `apps/worker/src/svgNetlist.js` now escapes netlist string values and keys before SVG serialization, called from `netlistRenderThread.js`. This covers both top-module and on-demand module rendering. All three regression tests passed, covering injected script markup, event-handler attributes, ordinary gate labels, and submodule hotspots. The same local Chromium test confirmed that the fixed SVG loads with the payload as escaped text and does not execute it. The fix does not modify already stored SVG: deploy the updated worker and regenerate existing SVG artifacts before treating those artifacts as remediated. No deployment or database cleanup was performed.

### 8. Tutorial solutions are publicly served despite the UI gate

**Source/configuration finding; no live access test.** These files under `apps/frontend/public` contain `SOLUTION_START` sections and are served as static assets without authentication by `apps/frontend/nginx.conf`:

- `/Tutorial/VerilogTutorialFormatted.md`
- `/Tutorial/VerilogTutorialFormatted_old.md`
- `/Kurse/ES1/ES1Tutorial.md`

The solution password and admin/developer checks in `apps/frontend/src/components/TutorialLesson.jsx` only control UI visibility. The password is bundled in the frontend, and the full solution content is already delivered to the browser. Direct requests for the Markdown bypass that gate without signing in.

**Remediation if solutions are intended to be restricted:** remove solutions, including legacy copies, from public assets and return them through a backend endpoint enforcing the intended permission. Protecting the React page alone does not protect static files. If solutions are intentionally public, document that the gate is only a convenience feature.

### 9. Public registration grants immediate simulation access

**Source finding; policy-dependent impact.** `POST /api/auth/register` in `apps/backend/src/routes/auth.js` allows self-registration and immediately issues a JWT with the `user` role. No email verification, institutional membership check, or account approval is required in that path. Authenticated users can then access the simulation endpoints, subject to their existing limits.

This is not an authentication bypass: it means the execution service is available to anyone able to register, rather than only approved students or staff. If open access is intended, this behavior is expected. If execution should be restricted, enforce admission requirements before granting simulation access; merely requiring a JWT is insufficient.

### 10. Cleanup gaps can retain jobs, files, and user data

| Location | Finding and impact | Verification |
| --- | --- | --- |
| `apps/worker/src/sandbox.js:36`, `dockerRunner.js:184`, `boardRunner.js:83` | Temporary-directory removal is not awaited by either runner, and `removeJobDir()` silently discards deletion errors. Jobs can finish before cleanup completes; failed deletions can retain source files and consume host storage without an alert. | Source inspection; no live deletion failure injected. |
| `apps/worker/src/sandbox.js:89`, `apps/worker/src/index.js` | Container deadlines depend on the worker's in-process timers. No shutdown cleanup or startup reconciliation of leftover simulation containers/job directories was found. Docker cleanup command failures are ignored. A worker crash can leave jobs running without their timeout; `--rm` removes containers when they exit, not when the worker dies. | Source inspection and Docker lifecycle documentation; no live worker-crash test. |
| `apps/frontend/src/contexts/AuthContext.jsx:164`, `apps/frontend/src/App.jsx:257` | Logout removes the authentication token but leaves editor projects/testbench contents under the shared `hdlab-projects` and `hdlab-active-project` localStorage keys, without resetting in-memory project state. Another account in the same browser profile can inherit those local drafts. | Source inspection; no end-to-end account-switch test. |
| `apps/backend/src/routes/tutorial.js:271` | The module-delete endpoint uses `deleteOne()` despite versioned storage. It reports success while other versions remain. Module-library records have no automatic TTL expiry. | Source inspection; no live database deletion test. |
| `apps/frontend/src/hooks/useSimArtifacts.js:73` | An in-flight module fetch can create and cache a Blob URL after unmount cleanup has already run. The URL is then not revoked, retaining memory until document teardown. | Reproduced with the actual hook logic, mocked React hooks/API responses, and tracked object-URL calls: one URL created after cleanup, none revoked. No live browser unmount test. |

The named-pipe issue in finding 2 also prevents the simulation runner from reaching its `finally` cleanup. These observations do not demonstrate access to another user's server-side records or a container escape; the local-draft exposure is specific to a shared browser profile.

**Remediation:** await directory deletion and surface/retry failures; track active containers and reconcile abandoned jobs with an independent deadline/cleanup mechanism. Confirm container termination before removing mounted job files. Reset account-specific browser state on logout/account changes and define how local drafts are retained; account-specific storage keys alone do not make browser storage confidential. Delete all versions within the authenticated user's scope when a full module deletion is requested. Invalidate pending artifact loads on unmount and revoke any URLs created after cancellation.

### 11. Tokens issued in the password-change second survive invalidation

**Confirmed in an isolated middleware test with verified-token claims and user lookup mocked.** `apps/backend/src/middleware/auth.js:29` rounds `passwordChangedAt` down to whole seconds and rejects tokens only when `decoded.iat < changedAt`. A token issued before the password change, but within the same second, therefore remains accepted. The test confirmed that same-second claims were accepted while prior-second claims were rejected. JWT signature verification was not under test.

Password reset and GitLab account linking both use this invalidation mechanism. A previously obtained token from that narrow time window can remain usable until its seven-day expiry, unless a later credential change or account deletion invalidates it. This does not allow an attacker to forge a token or bypass password verification.

**Remediation:** include an account session-version counter in tokens and compare it with the current database value on every authenticated request. Atomically increment it when resetting credentials or linking accounts so invalidation does not depend on timestamp precision.

### 12. A password-reset token can be redeemed concurrently more than once

**Confirmed using the actual reset handler with mocked database snapshots and password hashing.** `apps/backend/src/routes/auth.js:233` looks up the reset-token hash and expiry, then hashes the replacement password and saves the user separately. Two concurrent requests can both read the valid token before either clears it. Both local test requests returned success, and the later save determined the password.

This violates the intended single-use guarantee. Exploitation requires possession of a valid reset token and racing its redemption; no token disclosure, guessing, or unauthenticated account takeover was demonstrated. A sequential reuse after the token is cleared remains rejected.

**Remediation:** atomically match the token hash and unexpired deadline, set the replacement password, consume the token, and invalidate existing sessions. Only the request that successfully updates the matching record should return success. [OWASP password-reset guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) recommends single-use reset tokens.

### 13. Concurrent login attempts exceed the intended failure limits

**Confirmed using the actual login handler and limiter with mocked user lookup and asynchronous password comparison.** `apps/backend/src/routes/auth.js:129` checks the account/IP failure counters before database lookup and password comparison, but increments them only after those asynchronous operations fail. Concurrent attempts can all pass the initial check before any failure is recorded.

Twelve simultaneous invalid attempts against one username all reached password comparison and returned HTTP 401 despite the ten-failure account threshold; a subsequent request returned HTTP 429. This permits additional guesses and expensive password comparisons within a concurrent burst. It does not make the limiter ineffective against later requests or demonstrate successful login.

**Remediation:** reserve attempt capacity before asynchronous work and enforce a separate bound on concurrent password comparisons. Apply account and IP controls consistently, using shared atomic state if the backend runs in multiple processes.

### 14. Concurrent submissions exceed the active-simulation quota

**Confirmed using the actual simulation service with mocked database and queue operations.** `apps/backend/src/services/simulations.js:101` counts active simulations separately from inserting and queuing the next simulation. Starting with five active records, two concurrent calls both passed the six-active-simulation check, resulting in seven records and two queued messages.

The account quota therefore does not reliably bound outstanding submissions under concurrency. Worker concurrency and container resource limits remain effective; this finding concerns queue admission and fairness rather than unrestricted simultaneous container execution.

**Remediation:** atomically reserve per-account capacity before creating and queuing a simulation. Release reservations on completion/failure and reconcile abandoned reservations after crashes. Retain request rate limits as an additional control.

### 15. Module version updates bypass the total document quota

**Confirmed using the actual PATCH handler with mocked module storage and pruning queries.** `POST /modules` checks the 1,000-document account limit, but `PATCH /modules/:moduleName` in `apps/backend/src/routes/tutorial.js:245` creates a new version without applying that limit. A local test starting at 1,000 documents accepted a PATCH and increased the total to 1,001 without invoking the quota check.

The twenty-version limit per module name still applies. However, updates across existing module names can exceed the intended total storage allowance. Ownership checks remain present; this is a storage-abuse control gap, not access to another user's modules.

**Remediation:** enforce a common, concurrency-safe account storage quota across both creation and version-update paths. Account for versions removed by pruning and release storage reservations when records are deleted.

## What is implemented well

- Each job gets a separate container and job-directory mount. Submissions receive neither the worker's Docker socket nor its application credentials.
- Containers run as UID/GID 65534 with networking disabled, all capabilities dropped, and `no-new-privileges`. Memory, swap, CPU, process count, individual file size, and execution time are limited.
- Docker is invoked with an argument array. Filenames and top-module names have allowlists; project files have count and duplicate checks; simulation settings are explicitly selected. Ownership comes from authentication. Login rejects object-valued credentials.
- Registration, login, and password-reset inputs have explicit type and format checks. `testbenchType` also has a Mongoose enum, so absence of route-level validation does not mean it is unrestricted.
- All reviewed project, simulation, progress, module-library, and tutorial-validation API routes require authentication. Project/simulation access checks ownership; progress and library queries are scoped to the authenticated user. No private-data or simulation API route missing authentication was found in this source review.
- Public health, authentication, recovery, provider-status, and OAuth entry/callback routes have legitimate unauthenticated purposes. Password reset requires a separate reset token; the OAuth callback checks browser-bound state. Their absence of bearer authentication is not itself a finding.
- Artifact reads have size limits and reject symlinks. These controls remain useful despite the named-pipe defect.
- The reviewed SVG route sets an SVG content type, attachment disposition, restrictive CSP, and `nosniff`. The frontend's image preview also prevents SVG script execution. These controls protect those contexts; finding 7 describes the separate Blob-document risk and its source fix.
- Ordinary UI text and logs use React text rendering. Tutorial HTML passes through `rehype-sanitize`; local rendering tests removed script tags, event handlers, and JavaScript links. No additional XSS execution path was confirmed in that review.
- Normal container exits use `--rm`, simulation runners have `finally` cleanup blocks, artifact readers close file handles, and simulation-related MongoDB schemas define seven-day TTL indexes. Effective production indexes were not inspected, and TTL cleanup is asynchronous. These controls do not cover every failure path described in finding 10.

The worker itself mounts the Docker socket and processes attacker-controlled netlist JSON outside the simulation container. This increases the consequence of a worker compromise; no worker RCE was established. A Node worker thread is not a separate security sandbox.

## Browser WebAssembly option

Browser execution can remove server-side execution of submitted programs if both compilation and execution move to the client. HDLab already runs board simulation in a browser worker and uses YoWASP inside its container. [YoWASP supports browser-based Yosys](https://yowasp.org/), making board synthesis the clearest first migration candidate.

In a browser runtime without bridges to native execution, submitted code cannot launch the server's shell, inspect its kernel, access its filesystem, or issue system calls against it. `$system` and Python subprocess operations would need to be unsupported or replaced with deliberately limited browser implementations. File access can be confined to a temporary virtual filesystem and explicitly supplied project files. This would hinder the environment reconnaissance and native command execution described above, and remove the direct container-to-server-kernel attack path for jobs fully migrated to the browser. Any remaining server-side compilation or artifact processing still needs protection.

Full Verilator/Cocotb parity requires a separate prototype: Verilator produces C++ that also needs compilation, while [Cocotb depends on native simulator interfaces](https://docs.cocotb.org/en/stable/library_reference_c.html). Pyodide alone does not replace that integration.

Run hostile browser code on a separate origin without application credentials, restrict exposed APIs/network access, and terminate runaway workers. [Wasm security depends on its host interfaces](https://webassembly.org/docs/security/); [Pyodide exposes JavaScript interoperability](https://pyodide.org/en/stable/usage/type-conversions.html). Browser-generated pass/fail results cannot serve as authoritative grading without independent verification.

## Prioritized follow-up audit targets

These are proposed checks, not additional confirmed vulnerabilities. They extend the targeted review above; production isolation and two-account authorization tests should come first.

| Priority | Area | Checks |
| --- | --- | --- |
| 1 | Effective production isolation | Inspect actual container mounts, capabilities, seccomp/AppArmor policies, network reachability, kernel/runtime patches, and separation from application/database infrastructure. Compare deployed settings with the repository configuration. |
| 2 | Worker and queue permissions | Check whether backend/worker credentials can publish arbitrary jobs, access unrelated database collections, or control the Docker daemon. Establish the minimum permissions needed by each component. |
| 3 | Resource exhaustion and concurrency | Verify fixes for the isolated admission/quota bypasses in findings 14–15 against real concurrent database requests. Test queue saturation, many-account abuse, total disk/inode consumption, and expensive netlist/VCD parsing. Verify limits during failures and restarts. |
| 4 | Cross-account access | Use two test accounts to exchange project, simulation, artifact, and module identifiers. Verify ownership on reads, modifications, and deletions, including malformed selectors and missing resources. |
| 5 | Account and session lifecycle | Verify fixes for findings 11–13 with real tokens, password hashing, and concurrent database requests. Extend coverage to OAuth account linking, logout behavior, and account enumeration. |
| 6 | Hostile file handling | Test ZIP traversal, decompression bombs, duplicate/reserved filenames, symlinks, hard links, special files, and deeply nested or malformed artifacts. Include processing outside the simulation container. |
| 7 | Dependencies and build pipeline | Review native tools, npm/Python packages, container images, tutorial synchronization, CI permissions, and possible secret exposure through build contexts or frontend bundles. |
| 8 | Detection and recovery | Verify alerts for failed cleanup, abnormal job duration, disk pressure, repeated crashes, and rejected requests. Test backup restoration and check that logs avoid unnecessary credentials and submitted source. |

Supporting guidance: [OWASP Docker security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html), [authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [denial of service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html), and [software supply-chain security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html).

## References for container controls

- [Docker security model](https://docs.docker.com/engine/security/): native containers share the host kernel; isolation is not an absolute escape guarantee.
- [Docker logging](https://docs.docker.com/engine/logging/configure/): daemon defaults apply unless overridden for each container.
- [Docker networking disabled](https://docs.docker.com/engine/network/drivers/none/): loopback remains available; this setting does not disable all socket operations.
- [Docker container lifecycle](https://docs.docker.com/reference/cli/docker/container/run/): `--rm` removes a container when it exits.
- [MongoDB TTL indexes](https://www.mongodb.com/docs/manual/core/index-ttl/): expiry is performed asynchronously rather than at an exact deadline.
