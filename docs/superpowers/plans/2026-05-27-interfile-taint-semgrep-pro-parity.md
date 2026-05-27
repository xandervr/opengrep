# Interfile Taint Semgrep Pro Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring OpenGrep OSS interfile taint analysis as close as practical to Semgrep Pro behavior: cross-function, cross-file taint propagation with useful traces across every parsed AST language that can run taint mode.

**Architecture:** The current implementation builds per-file global taint environments and function signatures, resolves interfile calls through `Graph_from_AST`, and consumes signatures in `Dataflow_tainting`. Continue closing parity gaps by writing focused e2e regressions first, proving them red in Docker, then extending the existing naming/import/export/signature paths rather than adding a separate analyzer.

**Tech Stack:** OCaml engine (`src/tainting`, `src/engine`, `src/analyzing`, `src/naming`), Python e2e harness (`cli/tests/default/e2e`), OpenGrep CLI/core binaries built with Docker and `make core`.

---

## Pickup Summary

**Last updated:** 2026-05-27

**Workspace:** `/Users/xander/Documents/Work/Aikido/Projects.nosync/opengrep`

**Branch:** `codex/interfile-taint-mvp`

**Hard constraints:**
- Compile and verify through Docker only. The user explicitly rejected local compilation as the authoritative build path.
- Preserve support for every parser-backed target language in `cli/src/semgrep/semgrep_interfaces/lang.json`.
- Do not claim full Semgrep Pro parity until the remaining audit covers the full objective. `generic` and `regex` are now explicitly classified as non-AST analyzers outside Semgrep Pro taint parity scope.

**Completed and pushed on `codex/interfile-taint-mvp`:**
- CommonJS default exports, named function exports, and named object exports have Docker-verified interfile taint findings.
- Vue target parsing has been restored for `<script>` sections and is covered by Docker-verified language-matrix, parser-smoke, and trace checks.
- Static fixture coverage now checks all 45 `lang.json` target-language IDs, normalizing accepted aliases such as `javascript` to `js` and `typescript` to `ts`.
- Direct Docker scans passed for JS, CommonJS, imported values, Java, Python, Go, Elixir, the 28-finding language matrix, and the 13-finding parser smoke suite.
- `generic` and `regex` taint are now explicitly rejected with a structured `SemgrepError`, and CLI help no longer promises a fallback that cannot run.
- JavaScript interfile sanitizer and propagator fixtures now cover imported sanitizer functions and imported side-effect propagator functions.
- Python imported side-effect sanitizers now propagate across signatures through a `CleanLval` effect. Docker red/green proof showed `sink(data)` at line 8 disappear while `sink(unsafe)` at line 10 remains.
- Python inherited methods now resolve through the interfile call graph. `Graph_from_AST` builds a class hierarchy from `ClassDef.cextends` and searches subclass methods before parent methods for ordinary calls, top-level calls, chained constructor calls, static/class calls, and callback lookup.
- Inherited constructors now resolve through class lineage. A three-language fixture covers base constructors that set tainted fields and inherited methods that return those fields on Java, JavaScript, and Python subclass instances.

**Latest pushed checkpoints:**
- `7fcd695b511d5aa8b3542a410f79052c68211531` - `feat: add interfile taint analysis`
- `47d785905a858ea1f0ef5e22b2ae6980cdca9db4` - `fix: propagate interfile side-effect sanitizers`
- `b6838a1d4ad2995a765d6cfef7174e52531271b8` - `docs: update interfile taint handoff`
- `8c72876d684d9bc334d8a8e2a12bcdbd91189972` - `fix: resolve inherited interfile methods`
- `49ef0429b86541142b38a2c51f2a8c1eec90530b` - `docs: record inherited interfile taint checkpoint`
- `8efc77cbb7e34557466600e143729725f801f9c5` - `fix: resolve inherited constructors in interfile taint`

**Resolved decision:** Track A was chosen for `generic`/`regex`: keep interfile taint scoped to dedicated-parser languages. Semgrep's current public docs describe interfile analysis as a Semgrep Pro feature for a subset of languages and list Generic as `N/a` in Semgrep Code support, while OpenGrep's `Xtarget` documents that generic/regex analyzers do not have a lazy AST. Implementing real taint support for these analyzers would require a separate non-AST dataflow engine, not a small fallback.

Current Docker proof for unsupported generic/regex taint:

```text
generic_taint results=0 errors=1
2    error    SemgrepError at line /tmp/opengrep-generic-regex/target.txt:1:
 taint mode requires a dedicated parser; generic and regex analyzers do not support taint analysis
regex_taint results=0 errors=1
2    error    SemgrepError at line /tmp/opengrep-generic-regex/target.txt:1:
 taint mode requires a dedicated parser; generic and regex analyzers do not support taint analysis
```

The Docker-built help text now says:

```text
--taint-intrafile
    Enable intra-file inter-procedural taint analysis. Supported for
    languages with a dedicated parser. Generic and regex analyzers do
    not support taint mode.
```

**Immediate resume point:** continue the broader Semgrep Pro parity audit. Do not reopen generic/regex unless the user explicitly wants non-Semgrep-Pro behavior for those extended analyzers.

**Next concrete actions:**

1. Re-run the Docker direct scan matrix from Task 4 after any further engine change.
2. Keep `git diff --check` and `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` green.
3. Continue auditing remaining Semgrep Pro parity gaps beyond the covered import/value/export/object/trace/inheritance cases.
4. A separate probe showed Java inherited constructors work when fields are accessed as `this.value`, but the same shape with unqualified `value` still produced 0 findings. Treat unqualified Java instance-field access as a separate audit item, not part of the inherited-constructor regression.

Latest side-effect sanitizer verification:

```text
taint_interfile_python_side_effect_sanitizer count=1 expected=1 errors=0 interfile_lang_count=1
```

Latest Python inheritance red proof before `8c72876d`:

```text
taint_interfile_python_inheritance count=0 expected=1 errors=0 interfile_lang_count=1
```

Latest Python inheritance green proof after `8c72876d`:

```text
taint_interfile_python_inheritance count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_python_inheritance    targets/taint_interfile_python_inheritance/app.py    6
```

Latest inherited-constructor red proof before `8efc77cbb`:

```text
taint_interfile_inherited_constructor count=0 expected=3 errors=0 interfile_lang_count=3
```

Latest inherited-constructor green proof after `8efc77cbb`:

```text
taint_interfile_inherited_constructor count=3 expected=3 errors=0 interfile_lang_count=3
rules.taint_interfile_inherited_constructor_java    targets/taint_interfile_inherited_constructor/java/App.java    4
rules.taint_interfile_inherited_constructor_js    targets/taint_interfile_inherited_constructor/javascript/app.js    5
rules.taint_interfile_inherited_constructor_python    targets/taint_interfile_inherited_constructor/python/app.py    6
```

Latest broad Docker direct scan matrix after `8efc77cbb`:

```text
taint_interfile_js count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_commonjs count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_imported_value count=2 expected=2 errors=0 interfile_lang_count=1
taint_interfile_js_object_method count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_sanitizer count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_propagator count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_imported_value_package_collision count=2 expected=2 errors=0 interfile_lang_count=2
taint_interfile_java count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_python count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_python_module_import count=2 expected=2 errors=0 interfile_lang_count=1
taint_interfile_python_duplicate_names count=2 expected=2 errors=0 interfile_lang_count=1
taint_interfile_python_class_instance count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_python_inheritance count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_inherited_constructor count=3 expected=3 errors=0 interfile_lang_count=3
taint_interfile_python_imported_value count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_python_wildcard_import count=2 expected=2 errors=0 interfile_lang_count=1
taint_interfile_python_sanitizer count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_python_side_effect_sanitizer count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_go count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_elixir count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13
```

Historical generic/regex reproduction command:

```bash
docker run --rm --volume opengrep-src-build:/src --workdir /src/opengrep/cli/tests/default/e2e alpine:3.22 sh -lc '
set -e
apk add --no-cache pcre pcre2 gmp libev jq >/dev/null
mkdir -p /tmp/opengrep-generic-regex
cat > /tmp/opengrep-generic-regex/target.txt <<EOF
source()
sink(source())
EOF
cat > /tmp/opengrep-generic-regex/generic.yaml <<EOF
rules:
- id: generic-taint
  mode: taint
  languages: [generic]
  pattern-sources:
  - pattern: source()
  pattern-sinks:
  - pattern: sink(...)
  message: generic taint
  severity: WARNING
EOF
cat > /tmp/opengrep-generic-regex/regex.yaml <<EOF
rules:
- id: regex-taint
  mode: taint
  languages: [regex]
  pattern-sources:
  - pattern-regex: source\\(\\)
  pattern-sinks:
  - pattern-regex: sink\\(
  message: regex taint
  severity: WARNING
EOF
/src/opengrep/bin/opengrep scan --config /tmp/opengrep-generic-regex/generic.yaml --json --no-git-ignore --x-ignore-semgrepignore-files /tmp/opengrep-generic-regex/target.txt > /tmp/opengrep-generic-regex/generic.json || true
/src/opengrep/bin/opengrep scan --config /tmp/opengrep-generic-regex/regex.yaml --json --no-git-ignore --x-ignore-semgrepignore-files /tmp/opengrep-generic-regex/target.txt > /tmp/opengrep-generic-regex/regex.json || true
printf "generic_taint results=%s errors=%s\n" "$(jq -r ".results|length" /tmp/opengrep-generic-regex/generic.json)" "$(jq -r ".errors|length" /tmp/opengrep-generic-regex/generic.json)"
jq -r ".errors[]?.message // .errors[]? // empty" /tmp/opengrep-generic-regex/generic.json
printf "regex_taint results=%s errors=%s\n" "$(jq -r ".results|length" /tmp/opengrep-generic-regex/regex.json)" "$(jq -r ".errors|length" /tmp/opengrep-generic-regex/regex.json)"
jq -r ".errors[]?.message // .errors[]? // empty" /tmp/opengrep-generic-regex/regex.json
'
```

## Current State Snapshot

Worktree is expected to be clean after the latest pushed checkpoints. Verify with `git status -sb` before resuming.

Major engine files touched by the interfile taint branch:
- `src/tainting/Dataflow_tainting.ml`
- `src/tainting/Dataflow_tainting.mli`
- `src/tainting/Graph_from_AST.ml`
- `src/tainting/Graph_from_AST.mli`
- `src/tainting/Taint_input_env.ml`
- `src/tainting/Taint_lval_env.ml`
- `src/tainting/Taint_signature_extractor.ml`
- `src/engine/Match_tainting_mode.ml`
- `src/engine/Match_taint_spec.ml`
- `src/core_scan/Core_scan.ml`
- `src/analyzing/AST_modifications.ml`
- `src/analyzing/AST_to_IL.ml`
- `src/analyzing/Implicit_return.ml`
- `src/analyzing/Visit_function_defs.ml`
- `src/naming/Naming_AST.ml`
- `src/matching/Match_patterns.ml`
- `src/parsing/Parse_target.ml`
- `src/parsing_languages/Parse_target2.ml`
- `languages/typescript/tree-sitter/Parse_typescript_tree_sitter.ml`
- `languages/typescript/tree-sitter/Parse_typescript_tree_sitter.mli`
- `src/osemgrep/cli_scan/Scan_CLI.ml`
- `src/osemgrep/cli_test/Test_CLI.ml`

Major new e2e coverage:
- `cli/tests/default/e2e/test_taint_interfile.py`
- `cli/tests/default/e2e/rules/taint_interfile_*.yaml`
- `cli/tests/default/e2e/targets/taint_interfile_*/`

Verified in this handoff:
- Docker `make core` completed successfully.
- Focused direct scans passed for JS imports, JS CommonJS default export, JS object method, package collision, Python imports, Java, Go, and Elixir.
- Focused direct scans passed for JavaScript interfile sanitizer and propagator behavior.
- Focused direct scans passed for Python imported side-effect sanitizers and inherited Python methods.
- Focused direct scans passed for inherited constructors in Java, JavaScript, and Python.
- Broad direct scans passed for `taint_interfile_language_matrix` with 28 findings and `taint_interfile_parser_smoke` with 13 findings.
- `--dataflow-traces` on `taint_interfile_js` produced cross-file source, intermediate variable, and sink trace locations.
- `--dataflow-traces` on the Vue language-matrix fixture produced cross-file source, intermediate variable, and sink trace locations.
- Direct probes showed basic Java, JavaScript, TypeScript, and Python instance dispatch works.
- Direct probes showed field-backed object flows through constructors/methods work for Java, JavaScript, and Python.

Known boundaries:
- `generic` and `regex` are extended non-AST analyzers, not parser-backed target languages. Taint mode now rejects them with a structured `SemgrepError` and CLI help documents that they do not support taint mode.
- Do not claim full Semgrep Pro parity until a requirement-by-requirement audit proves it.

Docker-only instruction:
- The user explicitly said to compile in Docker. Do not use local opam/dune builds as the authoritative build gate.

---

## Latest Session Update: Vue and CommonJS Green

Vue is still printed by `opengrep show supported-languages`, so it is treated as in scope for "all languages supported by opengrep." The old target parser branch failed with `Vue support has been removed in 1.93.0`; the current implementation restores Vue taint coverage by extracting `<script>` bodies with original byte/line positions preserved and feeding them through the existing TypeScript/TSX parser and JS generic conversion.

- `src/parsing_languages/Parse_target2.ml` now parses Vue targets through `parse_vue_script`.
- `languages/typescript/tree-sitter/Parse_typescript_tree_sitter.ml` now exposes `parse_string ~src_file`, preserving original source positions for transformed input.
- `src/tainting/Graph_from_AST.ml` now treats `.vue` as a known source extension so imports such as `./source.vue` resolve to `source.vue` files during interfile graph construction.
- `cli/tests/default/e2e/rules/taint_interfile_language_matrix.yaml` and `targets/taint_interfile_language_matrix/vue/` add a three-file Vue interfile flow.
- `cli/tests/default/e2e/rules/taint_interfile_parser_smoke.yaml` and `targets/taint_interfile_parser_smoke/vue/` add a single-file Vue parser smoke taint flow.

Vue red proof before the fix:

```text
taint_interfile_matrix_vue_red count=0 expected=1 errors=1
Failure: Vue support has been removed in 1.93.0
taint_interfile_smoke_vue_red count=0 expected=1 errors=1
Failure: Vue support has been removed in 1.93.0
```

Vue green proof after the fix:

```text
taint_interfile_matrix_vue count=1 expected=1 errors=0
rules.taint_interfile_matrix_vue    targets/taint_interfile_language_matrix/vue/app.vue    5
taint_interfile_smoke_vue count=1 expected=1 errors=0
rules.taint_interfile_smoke_vue    targets/taint_interfile_parser_smoke/vue/app.vue    3
```

Current broad verification:

```text
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13
```

Vue trace verification:

```text
vue trace checks passed
```

The CommonJS named-function and named-object export regressions are also fixed in the Docker-built binary.

- `src/analyzing/Visit_function_defs.ml` now recognizes `module.exports.<name> = function (...) { ... }` as a named function definition.
- `src/engine/Match_tainting_mode.ml` now separates signature extraction from function checking so checks run with the final signature database.
- `src/tainting/Graph_from_AST.ml` now prefers same-file unqualified function candidates before arity disambiguation. Root cause: top-level `main()` in `named_app.js` was resolving to `app.js`'s `main`, so the `getUser -> named_app main` edge was pruned from the relevant subgraph.
- `src/tainting/Graph_from_AST.ml` now attributes source/sink ranges inside expression-assignment lambdas, including `module.exports.getUser = function (...) { ... }`, to the extracted function instead of `<top_level>`.
- `src/tainting/Taint_input_env.ml` now records `module.exports.api = { ... }` as an exported global, so destructured `require("./named_common")` can propagate through `api.getProfile()`.
- The original `analysis_order |> List.rev` remains restored. Removing it made the targeted CommonJS scan worse.

The Docker rebuild completed successfully only after rerunning the tree-sitter setup and installing static link dependencies. Use the Docker build command in Task 1 Step 4, not a local build.

Current targeted scan:

```text
taint_interfile_js_commonjs count=3 expected=3 errors=0
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/app.js    4
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    4
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    10
```

Current debug evidence after the fix:

```text
SUBGRAPH: source_function[0] = module.exports
SUBGRAPH: source_function[1] = getUser
SUBGRAPH: sink_function[0] = main
SUBGRAPH: sink_function[1] = main
SIG_FOUND: getUser:11 ->  => {return ({ [source() :l.2] } & _|_ & CTRL:{  })}
```

Fresh verification after the fix:

- Docker `make core` passes.
- Direct CommonJS scan returns all three expected findings.
- Focused direct regression matrix passes, including `taint_interfile_js_commonjs count=3 expected=3 errors=0 interfile_lang_count=1`, `taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28`, and `taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13`.
- `--dataflow-traces` checks pass for cross-file source, intermediate variable, and sink locations in JS and Vue.
- `test_interfile_taint_rule_fixtures_cover_all_target_languages` was added to lock the e2e rule set against all 45 `lang.json` target-language IDs.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue the completion audit around generic/regex and any remaining Semgrep Pro parity gaps before making any broad parity claim.

---

## Completed CommonJS Regression History

CommonJS named function and named object exports assigned through `module.exports.<name>` are now propagated through destructured `require`.

Current test files:

`cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_common.js`
```js
module.exports.getUser = function () {
  return source();
};

module.exports.api = {
  getProfile() {
    return source();
  },
};
```

`cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_app.js`
```js
const { getUser, api } = require("./named_common");

function main() {
  sink(getUser());
}

main();

function other() {
  sink(api.getProfile());
}

other();
```

`cli/tests/default/e2e/test_taint_interfile.py` now expects three CommonJS findings:
```python
assert len(results) == 3
assert {result["check_id"] for result in results} == {
    "rules.taint_interfile_js_commonjs"
}
assert {
    (result["path"], result["start"]["line"]) for result in results
} == {
    ("targets/taint_interfile_js_commonjs/app.js", 4),
    ("targets/taint_interfile_js_commonjs/named_app.js", 4),
    ("targets/taint_interfile_js_commonjs/named_app.js", 10),
}
```

Named function red proof before the fix:
```text
commonjs_named_export_red count=1 expected=2 errors=0
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/app.js    4
```

Named object red proof before the fix:
```text
taint_interfile_js_commonjs_object count=2 expected=3 errors=0
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/app.js    4
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    4
```

Current green proof:
```text
taint_interfile_js_commonjs_object count=3 expected=3 errors=0
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/app.js    4
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    10
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    4
```

Important AST evidence:
- In `named_app.js`, destructured `require("./named_common")` names `getUser` as `ImportedEntity ["./named_common"; "getUser"]`.
- In `named_common.js`, `module.exports.getUser = function () { return source(); }` appears as an assignment to `DotAccess(DotAccess(module, exports), getUser)` with a `Lambda`.
- In `named_app.js`, destructured `require("./named_common")` names `api` as `ImportedEntity ["./named_common"; "api"]`.
- In `named_common.js`, `module.exports.api = { getProfile() { return source(); } }` appears as an assignment to `DotAccess(DotAccess(module, exports), api)` with an object literal.

---

## Task 1: Fix CommonJS Named Function Exports

**Files:**
- Modify: `src/analyzing/Visit_function_defs.ml`
- Modify if needed: `src/tainting/Taint_input_env.ml`
- Modify if needed: `src/tainting/Graph_from_AST.ml`
- Test: `cli/tests/default/e2e/test_taint_interfile.py`
- Test target: `cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_common.js`
- Test target: `cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_app.js`

- [x] **Step 1: Confirm the red test still fails**

Run the named-function red proof command from the "Completed CommonJS Regression History" section.

Expected:
```text
commonjs_named_export_red count=1 expected=2 errors=0
```

- [x] **Step 2: Inspect named CommonJS AST in the current binary**

Run:
```bash
docker run --rm --volume opengrep-src-build:/src --volume "$PWD":/work --workdir /work alpine:3.22 sh -lc '
set -e
apk add --no-cache pcre pcre2 gmp libev >/dev/null
/src/opengrep/bin/opengrep-core -lang js -dump_named_ast cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_common.js | sed -n "1,220p"
'
```

Expected shape includes:
```text
Assign(
  DotAccess(
    DotAccess(
      N(Id(("module", ...))),
      ...,
      FN(Id(("exports", ...)))),
    ...,
    FN(Id(("getUser", ...)))),
  ...,
  Lambda(...))
```

- [x] **Step 3: Add function extraction for `module.exports.<name> = function`**

In `src/analyzing/Visit_function_defs.ml`, extend `extract_lambda_assignment` with a case before the fallback:

```ocaml
  | G.Assign
      ( {
          e =
            G.DotAccess
              ( {
                  e =
                    G.DotAccess
                      ( { e = G.N (G.Id (("module", _), _)); _ },
                        _,
                        G.FN (G.Id (("exports", _), _)) );
                  _;
                },
                _,
                G.FN (G.Id ((export_name, export_tok), export_id_info)) );
          _;
        },
        _,
        { e = G.Lambda fdef; _ } ) ->
      let ent =
        {
          G.name = G.EN (G.Id ((export_name, export_tok), export_id_info));
          attrs = [];
          tparams = None;
        }
      in
      Some (ent, fdef)
```

This should let the signature extractor and call graph see a file-local top-level function named `getUser`, which matches the existing `ImportedEntity ["./named_common"; "getUser"]` resolution path.

- [x] **Step 4: Rebuild in Docker**

Sync the repo into the Docker source volume if the current session uses the existing `opengrep-src-build` named volume:
```bash
docker run --rm --volume "$PWD":/work --volume opengrep-src-build:/src alpine:3.22 sh -lc '
rm -rf /src/opengrep
mkdir -p /src
cp -a /work /src/opengrep
'
```

Build:
```bash
docker run --rm \
  --volume opengrep-src-build:/src \
  --volume opengrep-opam-docker-5-3:/opam \
  --volume opengrep-dune-cache:/workspace/_dune \
  --workdir /src/opengrep \
  alpine:3.22 sh -lc '
set -e
apk add --no-cache bash build-base coreutils curl curl-dev curl-static gmp-dev gmp-static libev-dev libffi-dev libidn2-static libpsl-static libunistring-static linux-headers m4 musl-dev nghttp2-static opam openssl-libs-static pcre-dev pcre-static pcre2-dev pcre2-static perl pkgconf rsync tar unzip zip zlib-dev zlib-static zstd zstd-static brotli-static >/dev/null
cd libs/ocaml-tree-sitter-core
./configure >/dev/null
./scripts/install-tree-sitter-lib >/dev/null
cd /src/opengrep
opam exec --root=/opam --switch=5.3.0 -- make core
'
```

Expected final lines include:
```text
dune build _build/install/default/bin/opengrep-core
dune build _build/install/default/bin/opengrep-cli
dune build _build/install/default/bin/opengrep
```

- [x] **Step 5: Verify the CommonJS regression is green**

Run:
```bash
docker run --rm --volume opengrep-src-build:/src --workdir /src/opengrep/cli/tests/default/e2e alpine:3.22 sh -lc '
set -e
apk add --no-cache pcre pcre2 gmp libev jq >/dev/null
/src/opengrep/bin/opengrep scan --config rules/taint_interfile_js_commonjs.yaml --json --no-git-ignore --x-ignore-semgrepignore-files targets/taint_interfile_js_commonjs > /tmp/commonjs.json
count="$(jq -r ".results|length" /tmp/commonjs.json)"
errors="$(jq -r ".errors|length" /tmp/commonjs.json)"
printf "taint_interfile_js_commonjs count=%s expected=2 errors=%s\n" "$count" "$errors"
jq -r ".results[]? | [.check_id,.path,.start.line] | @tsv" /tmp/commonjs.json | sort
test "$count" = "2"
test "$errors" = "0"
'
```

Expected:
```text
taint_interfile_js_commonjs count=2 expected=2 errors=0
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/app.js    4
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    4
```

Current actual after the final fix:

```text
taint_interfile_js_commonjs count=2 expected=2 errors=0
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/app.js    4
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    4
```

- [x] **Step 6: Trace why final signature lookup misses the imported callee**

Patch `src/call_graph/Call_graph.ml` temporarily around `lookup_callee_from_graph` and rebuild in Docker. Capture:

- Whether `caller` is a graph vertex.
- The incoming edge count for `caller`.
- The `call_tok` position from dataflow.
- Each incoming edge label `call_site`.
- The chosen callee when a match is found.

Use this debug scan:

```bash
docker run --rm --volume opengrep-src-build:/src --workdir /src/opengrep/cli/tests/default/e2e alpine:3.22 sh -lc '
set -e
apk add --no-cache pcre pcre2 gmp libev jq grep >/dev/null
SEMGREP_LOG_LEVEL=debug SEMGREP_LOG_SRCS="semgrep.tainting,semgrep.call_graph" /src/opengrep/bin/opengrep scan --debug --config rules/taint_interfile_js_commonjs.yaml --json --no-git-ignore --x-ignore-semgrepignore-files targets/taint_interfile_js_commonjs > /tmp/commonjs_debug.json 2> /tmp/commonjs_debug.log || true
grep -En "getUser|named_common|CALL_EXTRACT|TAINT_SIGBUILD|SIG_FOUND|No signature found|TAINT_TOPO|CALL_GRAPH_LOOKUP" /tmp/commonjs_debug.log | sed -n "1,360p" || true
jq -r "{results:(.results|length), errors:(.errors|length)}" /tmp/commonjs_debug.json
'
```

- [x] **Step 7: Implement the missing signature resolution path**

Observed root cause: the imported `getUser -> named_app main` edge existed in the full call graph, but the top-level `main()` call in `named_app.js` resolved to `app.js`'s `main`, so relevant-subgraph pruning dropped the named-export path. The fix is same-file candidate preference in `src/tainting/Graph_from_AST.ml`, plus expression-assignment lambda source ownership. The imported-function fallback below was not needed for this regression, but remains a useful fallback design if a future imported-call lookup fails after the graph edge is correct.

Preferred location: the `Fetch { base = Var name; rev_offset = [] }` branch in `lookup_signature_with_object_context`.

Preferred behavior:

- Check `name.id_info.id_resolved` for `ImportedEntity`.
- Split the canonical import into provider path and export name.
- Find a matching signature in `Shape_and_sig.signature_database.signatures`.
- Match by export name and provider file suffix, not by the call-site token.
- Keep the fallback behind the imported-entity case only, so local same-name functions still use the call graph or normal direct lookup.

- [x] **Step 8: Rebuild and verify two CommonJS named-function findings**

Use the Docker sync and build commands from Step 4, then rerun Step 5. Task 1 was complete once the targeted CommonJS scan reported both `app.js:4` and `named_app.js:4`.

---

## Task 2: Add CommonJS Named Export Shape Coverage

**Files:**
- Modify: `cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_common.js`
- Modify: `cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_app.js`
- Modify: `cli/tests/default/e2e/test_taint_interfile.py`
- Modify if needed: `src/tainting/Taint_input_env.ml`
- Modify if needed: `src/tainting/Dataflow_tainting.ml`

- [x] **Step 1: Extend the red fixture with a named object export**

Append this to `cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_common.js`:
```js
module.exports.api = {
  getProfile() {
    return source();
  },
};
```

Append this to `cli/tests/default/e2e/targets/taint_interfile_js_commonjs/named_app.js`:
```js
const { api } = require("./named_common");

function other() {
  sink(api.getProfile());
}

other();
```

Update the CommonJS assertion in `cli/tests/default/e2e/test_taint_interfile.py` to expect three findings:
```python
assert len(results) == 3
assert {result["check_id"] for result in results} == {
    "rules.taint_interfile_js_commonjs"
}
assert {
    (result["path"], result["start"]["line"]) for result in results
} == {
    ("targets/taint_interfile_js_commonjs/app.js", 4),
    ("targets/taint_interfile_js_commonjs/named_app.js", 4),
    ("targets/taint_interfile_js_commonjs/named_app.js", 10),
}
```

- [x] **Step 2: Run the targeted scan and confirm the new shape is red**

The first targeted scan returned two findings instead of three:

```text
taint_interfile_js_commonjs_object count=2 expected=3 errors=0
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/app.js    4
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    4
```

- [x] **Step 3: Implement exported object global support**

`src/tainting/Taint_input_env.ml` now maps `module.exports.api = { getProfile() { ... } }` to an exported global `api`, which lets existing imported-global and object-method shape handling carry the `getProfile` function shape through destructured CommonJS imports.

- [x] **Step 4: Rebuild in Docker and verify three findings**

Use the Docker build command from Task 1 Step 4.

Run the targeted CommonJS scan with `expected=3`.

Current actual:
```text
taint_interfile_js_commonjs count=3 expected=3 errors=0
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/app.js    4
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    10
rules.taint_interfile_js_commonjs    targets/taint_interfile_js_commonjs/named_app.js    4
```

---

## Task 3: Re-evaluate Vue Language Advertising

**Files:**
- Inspect: `src/parsing_languages/Parse_target2.ml`
- Inspect: `src/parsing_languages/Parse_pattern2.ml`
- Inspect: `src/rule/Lang.ml`
- Inspect: `cli/src/semgrep/semgrep_interfaces/lang.json`
- Inspect: `cli/src/semgrep/semgrep_interfaces/Language.ml`
- Inspect deleted history: `languages/vue/generic/Parse_vue_tree_sitter.ml`

- [x] **Step 1: Confirm current Vue failure**

Run:
```bash
docker run --rm --volume opengrep-src-build:/src --workdir /src/opengrep alpine:3.22 sh -lc '
set -e
apk add --no-cache pcre pcre2 gmp libev jq >/dev/null
mkdir -p /tmp/vue
cat > /tmp/vue/app.vue <<EOF
<script>
function source() { return 1 }
function sink(x) {}
sink(source())
</script>
EOF
cat > /tmp/vue/rule.yaml <<EOF
rules:
- id: vue-taint
  mode: taint
  languages: [vue]
  pattern-sources:
  - pattern: source(...)
  pattern-sinks:
  - pattern: sink(...)
  message: taint
  severity: WARNING
EOF
/src/opengrep/bin/opengrep scan --config /tmp/vue/rule.yaml --json --no-git-ignore --x-ignore-semgrepignore-files /tmp/vue > /tmp/vue/out.json || true
jq -r "{results:(.results|length), errors:.errors}" /tmp/vue/out.json
'
```

Actual failure before the fix included:
```text
Failure: Vue support has been removed in 1.93.0
```

- [x] **Step 2: Decide with evidence whether Vue is in scope**

Vue cannot be made interfile-taint-compatible without parser support. Use this evidence:
```bash
git show --stat --name-status 15ee91147 | sed -n '1,120p'
git show 15ee91147^:languages/vue/generic/Parse_vue_tree_sitter.ml | sed -n '1,120p'
git show 15ee91147^:src/parsing_languages/Parse_target2.ml | sed -n '160,190p'
```

Decision: Vue is in scope because `opengrep show supported-languages` still prints `vue`, and the user explicitly asked for all languages supported by opengrep.

- [x] **Step 3: Add Vue red fixtures**

Added:
- `cli/tests/default/e2e/targets/taint_interfile_language_matrix/vue/source.vue`
- `cli/tests/default/e2e/targets/taint_interfile_language_matrix/vue/helpers.vue`
- `cli/tests/default/e2e/targets/taint_interfile_language_matrix/vue/app.vue`
- `cli/tests/default/e2e/targets/taint_interfile_parser_smoke/vue/app.vue`

Updated:
- `cli/tests/default/e2e/rules/taint_interfile_language_matrix.yaml`
- `cli/tests/default/e2e/rules/taint_interfile_parser_smoke.yaml`
- `cli/tests/default/e2e/test_taint_interfile.py`

Red proof:
```text
taint_interfile_matrix_vue_red count=0 expected=1 errors=1
taint_interfile_smoke_vue_red count=0 expected=1 errors=1
```

- [x] **Step 4: Implement Vue script parsing**

Implemented:
- `src/parsing_languages/Parse_target2.ml` extracts `<script>` content while preserving original byte and line positions.
- `languages/typescript/tree-sitter/Parse_typescript_tree_sitter.ml` exposes `parse_string ~src_file`.
- `src/tainting/Graph_from_AST.ml` recognizes `.vue` as a source extension for import/module path matching.

- [x] **Step 5: Rebuild in Docker and verify Vue**

Green proof:
```text
taint_interfile_matrix_vue count=1 expected=1 errors=0
rules.taint_interfile_matrix_vue    targets/taint_interfile_language_matrix/vue/app.vue    5
taint_interfile_smoke_vue count=1 expected=1 errors=0
rules.taint_interfile_smoke_vue    targets/taint_interfile_parser_smoke/vue/app.vue    3
```

---

## Task 4: Run the Full Direct Verification Matrix

**Files:**
- Read-only verification against current Docker build.

- [x] **Step 1: Rebuild in Docker**

Run the Docker build command from Task 1 Step 4.

- [x] **Step 2: Run focused and broad direct scans**

Run:
```bash
docker run --rm --volume opengrep-src-build:/src --workdir /src/opengrep/cli/tests/default/e2e alpine:3.22 sh -lc '
set -e
apk add --no-cache pcre pcre2 gmp libev jq >/dev/null
run_scan() {
  name="$1"
  expected="$2"
  config="rules/${name}.yaml"
  target="targets/${name}"
  out="/tmp/${name}.json"
  /src/opengrep/bin/opengrep scan --config "$config" --json --no-git-ignore --x-ignore-semgrepignore-files "$target" > "$out"
  count="$(jq -r ".results|length" "$out")"
  errors="$(jq -r ".errors|length" "$out")"
  lang_count="$(jq -r ".interfile_languages_used|length" "$out")"
  printf "%s count=%s expected=%s errors=%s interfile_lang_count=%s\n" "$name" "$count" "$expected" "$errors" "$lang_count"
  if [ "$count" != "$expected" ] || [ "$errors" != "0" ]; then
    jq -r ".results[]? | [.check_id,.path,.start.line] | @tsv" "$out" | sort
    jq -r ".errors[]?" "$out"
    exit 1
  fi
}
run_scan taint_interfile_js 1
run_scan taint_interfile_js_commonjs 3
run_scan taint_interfile_js_imported_value 2
run_scan taint_interfile_js_object_method 1
run_scan taint_interfile_js_sanitizer 1
run_scan taint_interfile_js_propagator 1
run_scan taint_interfile_imported_value_package_collision 2
run_scan taint_interfile_java 1
run_scan taint_interfile_python 1
run_scan taint_interfile_python_module_import 2
run_scan taint_interfile_python_duplicate_names 2
run_scan taint_interfile_python_class_instance 1
run_scan taint_interfile_python_imported_value 3
run_scan taint_interfile_python_wildcard_import 2
run_scan taint_interfile_python_sanitizer 1
run_scan taint_interfile_go 1
run_scan taint_interfile_elixir 1
run_scan taint_interfile_language_matrix 28
/src/opengrep/bin/opengrep scan --config rules/taint_interfile_parser_smoke.yaml --json --no-git-ignore --x-ignore-semgrepignore-files targets/taint_interfile_parser_smoke > /tmp/taint_interfile_parser_smoke.json
smoke_count="$(jq -r ".results|length" /tmp/taint_interfile_parser_smoke.json)"
smoke_errors="$(jq -r ".errors|length" /tmp/taint_interfile_parser_smoke.json)"
smoke_lang_count="$(jq -r ".interfile_languages_used|length" /tmp/taint_interfile_parser_smoke.json)"
printf "taint_interfile_parser_smoke count=%s expected=13 errors=%s interfile_lang_count=%s\n" "$smoke_count" "$smoke_errors" "$smoke_lang_count"
test "$smoke_count" = "13"
test "$smoke_errors" = "0"
'
```

Expected:
```text
taint_interfile_js_commonjs count=3 expected=3 errors=0
taint_interfile_js_sanitizer count=1 expected=1 errors=0
taint_interfile_js_propagator count=1 expected=1 errors=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13
```

- [x] **Step 3: Run dataflow trace verification**

Run:
```bash
docker run --rm --volume opengrep-src-build:/src --workdir /src/opengrep/cli/tests/default/e2e alpine:3.22 sh -lc '
set -e
apk add --no-cache pcre pcre2 gmp libev jq >/dev/null
/src/opengrep/bin/opengrep scan --config rules/taint_interfile_js.yaml --json --dataflow-traces --no-git-ignore --x-ignore-semgrepignore-files targets/taint_interfile_js > /tmp/interfile_trace.json
jq -e ".results[0].extra.dataflow_trace.taint_source[1][2][1][0].path == \"targets/taint_interfile_js/source.js\"" /tmp/interfile_trace.json
jq -e "([.results[0].extra.dataflow_trace.intermediate_vars[].location.path] | index(\"targets/taint_interfile_js/util.js\") != null)" /tmp/interfile_trace.json
jq -e ".results[0].extra.dataflow_trace.taint_sink[1][0].path == \"targets/taint_interfile_js/app.js\"" /tmp/interfile_trace.json
'
```

Expected: all three `jq -e` checks exit `0`.

Actual:
```text
js trace checks passed
vue trace checks passed
```

---

## Task 5: Run Pytest Harness for the New E2E File

**Files:**
- Test: `cli/tests/default/e2e/test_taint_interfile.py`

- [x] **Step 1: Inspect the e2e pytest path**

First inspect the existing e2e test invocation pattern:
```bash
rg -n "pytest .*test_taint_interfile|run_semgrep_in_tmp|kinda_slow" Makefile cli pyproject.toml tox.ini .github -g '*'
```

Current state:
- The pytest wrapper uses `pipenv run pytest`.
- `PYTEST_USE_OSEMGREP=true` disables Click runner and expects a real `opengrep`/`opengrep-core` executable.
- This checkout has `bin -> _build/install/default/bin`, but there are no local `bin/opengrep` or `bin/opengrep-core` artifacts because compilation is intentionally Docker-only.
- The authoritative executable is in the Docker `opengrep-src-build` volume, so the direct Docker scan matrix remains the current proof.
- A narrow pytest run for `test_interfile_taint_rule_fixtures_cover_all_target_languages` did not reach the test body because `pipenv run` created an empty virtualenv and failed importing `colorama` from `cli/tests/conftest.py`; that empty virtualenv was removed with `pipenv --rm`.

Do not claim pytest coverage until a Docker-compatible pytest invocation is wired up or the Docker-built artifacts are intentionally exposed to the pytest environment.

- [ ] **Step 2: Keep direct scans even if pytest passes**

The direct scan matrix is still required because it verifies the built Docker binary directly and prints the result counts for every fixture.

---

## Task 6: Completion Audit Before Any Parity Claim

**Files:**
- Inspect: `cli/tests/default/e2e/test_taint_interfile.py`
- Inspect: `src/rule/Lang.ml`
- Inspect: `src/parsing_languages/Parse_target2.ml`
- Inspect: current `git diff`
- Inspect: Docker scan outputs from Task 4

- [ ] **Step 1: Build an evidence table**

Create a final audit note in the PR or final message with these rows:

```text
Requirement: cross-file function taint
Evidence: direct scans for JS/Python/Java/Go/Elixir and 28-language matrix
Status: proven if Task 4 passes

Requirement: cross-file imported values
Evidence: taint_interfile_js_imported_value, taint_interfile_python_imported_value, package collision fixture
Status: proven if Task 4 passes

Requirement: CommonJS default and named exports
Evidence: taint_interfile_js_commonjs count and exact paths
Status: proven if Task 4 passes with three CommonJS findings

Requirement: object-method export/call flow
Evidence: taint_interfile_js_object_method and CommonJS named object export fixture
Status: proven if Task 4 passes

Requirement: all parsed AST languages
Evidence: Lang.t list compared to language matrix plus parser smoke
Status: proven for parsed AST taint-capable languages if Task 4 passes

Requirement: Vue
Evidence: Task 3 red/green scan, 28-language matrix, 13-language parser smoke, Vue trace check
Status: proven for Vue script-section taint if Task 4 passes

Requirement: generic/regex
Evidence: Semgrep docs list Generic as N/a for Semgrep Code support; OpenGrep Xtarget has no AST for generic/regex; Docker scan returns structured SemgrepError instead of a syntax error; CLI help says generic/regex do not support taint mode
Status: explicitly out of Semgrep Pro parity scope

Requirement: dataflow traces
Evidence: Task 4 Step 3
Status: proven if trace checks pass
```

Current generic/regex proof:
```text
generic_taint results=0 errors=1
2    error    SemgrepError at line /tmp/opengrep-generic-regex/target.txt:1:
 taint mode requires a dedicated parser; generic and regex analyzers do not support taint analysis
regex_taint results=0 errors=1
2    error    SemgrepError at line /tmp/opengrep-generic-regex/target.txt:1:
 taint mode requires a dedicated parser; generic and regex analyzers do not support taint analysis
```

Supported-language coverage audit:
```text
opengrep show supported-languages includes generic, regex, and vue.
lang.json target language ids: 45.
All 45 lang.json target-language IDs are covered by taint_interfile_*.yaml fixtures once accepted aliases such as javascript -> js and typescript -> ts are normalized.
Vue is now covered by direct matrix, parser smoke, and trace checks.
Generic and regex are advertised extended analyzer tags, not parser-backed target-language IDs; taint mode rejects them with a SemgrepError because there is no AST/IL for dataflow analysis.
```

- [ ] **Step 2: Run diff hygiene**

Run:
```bash
git diff --check
python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py
```

Expected: both commands exit `0`.

- [ ] **Step 3: Do not mark the goal complete unless the audit proves the full objective**

Keep the active goal open if any Semgrep Pro parity item remains unimplemented, indirectly verified, or unaudited.

---

## Resume Checklist

Start a new session with these commands:

```bash
cd /Users/xander/Documents/Work/Aikido/Projects.nosync/opengrep
git status --short
sed -n '1,340p' docs/superpowers/plans/2026-05-27-interfile-taint-semgrep-pro-parity.md
```

Then continue the broader Semgrep Pro parity audit from Task 6. The `generic`/`regex` decision is resolved as dedicated-parser-only parity unless the user explicitly changes the scope to require a non-Semgrep-Pro fallback for those extended analyzers.
