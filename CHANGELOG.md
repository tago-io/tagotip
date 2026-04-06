# Changelog

## TagoTiP 1.0 — Revision D (2026-04-06)

### New: Location suffix (`@=`) for non-location variables

Added `@=` as a variable suffix and body-level modifier, enabling a single variable to carry both a typed value and geographic coordinates. Previously, the `@=` token was only available as an operator (where location IS the value); it is now also a suffix that attaches location to number, string, or boolean variables.

**Before (Revision C):** Location required a separate variable:

```
PUSH|AUTH|SERIAL|[speed:=10;position@=39.74,-104.99]
```

**After (Revision D):** Location attaches directly via `@=` suffix:

```
PUSH|AUTH|SERIAL|[speed:=10@=39.74,-104.99]
```

**Suffix ordering:** `#UNIT @=LOCATION @TIMESTAMP ^GROUP {METADATA}`

**Body-level modifier ordering:** `@=LOCATION @TIMESTAMP ^GROUP {METADATA} [variables]`

**Parser disambiguation:** After `@`, check next character — `=` means location suffix, digit means timestamp suffix.

**Restrictions:** The `@=` suffix MUST NOT be used with the `@=` operator (the value is already a location).

**Affected sections in TagoTiP.md:**

- Section 6.1 — structured format overview
- Section 6.2 — body-level modifier table and ordering rule
- Section 6.3 — variable structure
- Section 6.3.2 — suffixes table and operator restriction
- Section 6.3.3 — full variable form example
- Section 6.4 — inheritance rules and examples
- Section 11.4 — location examples
- Section 11.6 — body-level defaults example
- Section 7.2 — PULL response format
- Section 12.2 — PUSH body parsing rules (body-level and variable-level)
- Section 13 — size comparison examples
- Section 14 — ABNF grammar (`body-mods`, `common-suffixes`)
- Section 15 — symbol reference

**Affected sections in TagoTiPs.md:**

- Section 13 — size comparison examples (full frame and headless inner frame)

**Migration:** Parsers must handle `@=` after values/units as a location suffix. The 1-char lookahead (`@=` vs `@DIGIT`) resolves all ambiguity. Frame builders can now attach location to any variable type using the suffix position.

---

## TagoTiP/S 1.0 — Revision D (2026-04-06)

No functional changes. Updated size comparison examples to reflect the location suffix addition in TagoTiP Revision D.

---

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

**Migration:** Reorder body-level modifiers from `^GROUP@TIMESTAMP` to `@TIMESTAMP^GROUP` in all frame builders and parsers.

---

## TagoTiP/S 1.0 — Revision C (2026-02-24)

No functional changes. Updated size comparison examples to reflect the body-level modifier reordering in TagoTiP Revision C.

---

## TagoTiP 1.0 — Revision B

Initial specification.

## TagoTiP/S 1.0 — Revision C

See [TagoTiPs.md](TagoTiPs.md) header for prior revision history.
