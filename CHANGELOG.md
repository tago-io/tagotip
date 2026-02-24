# Changelog

## TagoTiP 1.0 — Revision C (2026-02-24)

### Breaking: Body-level modifier ordering changed

Standardized the ordering of `@TIMESTAMP` and `^GROUP` between body-level modifiers and variable-level suffixes.

**Before (Revision B):** Body-level used `^GROUP @TIMESTAMP {METADATA}`, while variable-level used `#UNIT @TIMESTAMP ^GROUP {METADATA}`.

**After (Revision C):** Both levels now use `@TIMESTAMP` before `^GROUP`:

- Body-level: `@TIMESTAMP ^GROUP {METADATA} [variables]`
- Variable-level: `#UNIT @TIMESTAMP ^GROUP {METADATA}`

**Affected sections in TagoTiP.md:**

- Section 6.1 -- structured format overview
- Section 6.2 -- body-level modifier definition, table, and ordering rule
- Section 6.4 -- inheritance example
- Section 11.6 -- body-level defaults example
- Section 12.2 -- parsing step 3
- Section 13 -- size comparison examples
- Section 14 -- ABNF `body-mods` rule

**Affected sections in TagoTiPs.md:**

- Section 13 -- size comparison examples (full frame and headless inner frame)

**Affected sections in TagoTipServers.md:**

- Section 2.4 -- HTTP body example
- Section 3.3 -- MQTT payload example

**Migration:** Reorder body-level modifiers from `^GROUP@TIMESTAMP` to `@TIMESTAMP^GROUP` in all frame builders and parsers.

---

## TagoTiP/S 1.0 — Revision C (2026-02-24)

No functional changes. Updated size comparison examples to reflect the body-level modifier reordering in TagoTiP Revision C.

---

## TagoTiP 1.0 — Revision B

Initial draft specification.

## TagoTiP/S 1.0 — Revision C

See [TagoTiPs.md](TagoTiPs.md) header for prior revision history.
