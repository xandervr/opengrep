# Interfile Taint Semgrep Pro Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring OpenGrep OSS interfile taint analysis as close as practical to Semgrep Pro behavior: cross-function, cross-file taint propagation with useful traces across every parsed AST language that can run taint mode.

**Architecture:** The current implementation builds per-file global taint environments and function signatures, resolves interfile calls through `Graph_from_AST`, and consumes signatures in `Dataflow_tainting`. Continue closing parity gaps by writing focused e2e regressions first, proving them red in Docker, then extending the existing naming/import/export/signature paths rather than adding a separate analyzer.

**Tech Stack:** OCaml engine (`src/tainting`, `src/engine`, `src/analyzing`, `src/naming`), Python e2e harness (`cli/tests/default/e2e`), OpenGrep CLI/core binaries built with Docker and `make core`.

---

## Pickup Summary

**Last updated:** 2026-05-28

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
- Java unqualified instance-field access now canonicalizes `EnclosedVar` lvalues as implicit `this.<field>` for interfile signatures and local dataflow. This keeps `return value` aligned with constructor assignments to `this.value`.
- C# and Kotlin unqualified instance-field flows now use the same implicit receiver canonicalization. Kotlin class `init` blocks and field initializers are modeled as synthetic `Class:<name>` initializer signatures so `Helper()` applies `this.<field>` effects to the constructed receiver.
- Static class-field flows now propagate for Java and C# qualified/unqualified static field reads and JavaScript qualified static field reads.
- Higher-order callback flows are now covered for JavaScript and Python when a cross-file helper calls a callback with tainted data and either returns the callback result or lets the callback body report the sink.
- Callback imports now resolve relative to the caller file before falling back to suffix-only matching, so repeated `source`/`apply` helpers in sibling JavaScript/Python directories no longer suppress callback findings.
- Typed callback flows are now covered for Java, Kotlin, and C# function/delegate parameters in both callback-return and callback-body-sink forms.
- Callback-return flows are now covered across Ruby, Scala, Rust, Swift, PHP, Elixir, and Clojure syntax forms.
- JavaScript and TypeScript class-field helper instances now resolve through both the call graph and taint signature lookup, so `this.source.getInput()` can consume a cross-file `Source#getInput` signature.
- JavaScript and TypeScript constructor-assigned helper instances now resolve when constructors assign `this.source = new Source()` and later methods call `this.source.getInput()`.
- TypeScript constructor parameter properties now resolve when a typed parameter property such as `constructor(private source: Source)` is later used through `this.source.getInput()`.
- Callback-body-sink flows are now covered across Ruby, Scala, Rust, Swift, Elixir, and Clojure syntax forms.
- JavaScript constructor-parameter helper instances now resolve when constructors assign `this.source = source` and a call site passes `new Source()`, a local helper alias, a simple reassigned helper alias, a simple factory-returned helper, a factory-local helper alias, an arrow-function factory helper, a simple higher-order factory, a callable factory variable alias, a service-container object property, a destructured service-container property, a nested service-container property path, a mutated service-container property assignment, a spread service-container property, a rest service-container property, a nested mutated service-container alias, an object factory property, an inline object factory property, or a same-class conditional branch alias into `new App(...)`.

**Latest pushed checkpoints:**
- `7fcd695b511d5aa8b3542a410f79052c68211531` - `feat: add interfile taint analysis`
- `47d785905a858ea1f0ef5e22b2ae6980cdca9db4` - `fix: propagate interfile side-effect sanitizers`
- `b6838a1d4ad2995a765d6cfef7174e52531271b8` - `docs: update interfile taint handoff`
- `8c72876d684d9bc334d8a8e2a12bcdbd91189972` - `fix: resolve inherited interfile methods`
- `49ef0429b86541142b38a2c51f2a8c1eec90530b` - `docs: record inherited interfile taint checkpoint`
- `8efc77cbb7e34557466600e143729725f801f9c5` - `fix: resolve inherited constructors in interfile taint`
- `5520f09144759c58ceeae51a596a58cb2ec0b62f` - `fix: track unqualified java instance fields`
- `417d3b881d99608389b6de341746b66a972134b1` - `fix: resolve unqualified class fields across languages` (unsigned: local 1Password SSH signing and private-key fallback were blocked in this session)
- `9ef5934fe` - `fix: propagate static class fields` (unsigned for the same local signing issue)
- `3f20a1c50aa0a0c422c7a8db691625bc0584c6e9` - `test: cover interfile callback taint flows` (unsigned for the same local signing issue)
- `3b3aa6f15375c660b1fe5a2832194b00c7f57073` - `fix: resolve callback imports by caller path` (unsigned for the same local signing issue)
- `164fb8debd063f55046f3c42be735fc544aca1b7` - `test: cover typed interfile callbacks` (unsigned for the same local signing issue)
- `93d972c3e694399a0093379468455639181c6bd6` - `test: cover callback language matrix` (unsigned for the same local signing issue)
- `166fe1048fe20eb9c03f3efe45281375d5a7e33d` - `fix: resolve class field instance calls` (unsigned for the same local signing issue)
- `5bab44a727a835e290188e4ea302141d11f86ea9` - `fix: resolve constructor assigned instance calls` (unsigned for the same local signing issue)
- `36b5e3ad9bb957cacfba63c1eab9adc63dec7e44` - `fix: resolve typescript parameter properties` (unsigned for the same local signing issue)
- `a49884fa48965b0c17945d1ddeaa1045d2863859` - `test: cover callback body language matrix` (unsigned for the same local signing issue)
- `85d614ba757365a04f22fb2b112907fd7a4a94fa` - `docs: record callback body matrix checkpoint` (unsigned for the same local signing issue)
- `123748e9f555f615489927d055dc701bfb12ffc4` - `fix: resolve javascript constructor parameter instances` (unsigned for the same local signing issue)
- `304ac57879d2a374fb943ac2e399a1073b40cb38` - `docs: record javascript constructor parameter checkpoint` (unsigned for the same local signing issue)
- `e6ea4ccfa6a559e2f65b345332abc056d70fee34` - `fix: resolve javascript constructor parameter aliases` (unsigned for the same local signing issue)
- `8d4a4447b30389811c1e95f11e571f29827d2342` - `docs: record javascript constructor alias checkpoint` (unsigned for the same local signing issue)
- `15b877b990be4b1a732909bcc983cfd256ec85fc` - `fix: propagate javascript constructor helper aliases` (unsigned for the same local signing issue)
- `7e07d0aa16a5ac850762e360729571d87eba7908` - `docs: record javascript reassigned alias checkpoint` (unsigned for the same local signing issue)
- `71ba70c2f2393f74afc1619f5b6d7d1e4ca78acb` - `fix: resolve javascript constructor factory aliases` (unsigned for the same local signing issue)
- `71acd60311803d98ea4a9f98f4bb4a9f5bae4270` - `fix: resolve javascript constructor branch aliases` (unsigned for the same local signing issue)
- `5c61c4cfb6a05c0b513fdd99d87b9926a45bf219` - `fix: resolve javascript factory local aliases` (unsigned for the same local signing issue)
- `1c95ff0404b22ded79d9dce3a321e8c034983290` - `fix: resolve javascript arrow factories` (unsigned for the same local signing issue)
- `0f5e1714786f7b19e8c9537a53e91ed636f6e75f` - `fix: resolve javascript higher-order factories` (unsigned for the same local signing issue)
- `61f95414010bc05eaf7a33faaed1b8857c9447dc` - `fix: resolve javascript factory function aliases` (unsigned for the same local signing issue)
- `f7dcf305d934132c4a3b3a1fabca1ddbbd9d64d9` - `docs: record javascript factory function alias checkpoint` (unsigned for the same local signing issue)
- `5364c43d39edb947abc1643a435792aee79aefc8` - `fix: resolve javascript service containers` (unsigned for the same local signing issue)
- `496acb41dfc4cddb2f00e9d98ef7fbaf78c012e3` - `docs: record javascript service container checkpoint` (unsigned for the same local signing issue)
- `b5b37096f9c841042f2e47e4a4054d5dfbb001b4` - `fix: resolve javascript service destructuring` (unsigned for the same local signing issue)
- `c8003e10b69fb45d473a220d93d33c043c04acd7` - `docs: record javascript service destructuring checkpoint` (unsigned for the same local signing issue)
- `627365d38409908d4819f3a129a73f2baf597fa3` - `fix: resolve javascript nested service containers` (unsigned for the same local signing issue)
- `e1c9630e6474e03621d83e86a06a0f3d599ffcdb` - `docs: record javascript nested service container checkpoint` (unsigned for the same local signing issue)
- `229ef6e6f55c8c680924683e8217422c8861bbb2` - `fix: resolve javascript mutated service containers` (unsigned for the same local signing issue)
- `c6aff426751b91849f861142f088a0cd2d6f2add` - `docs: record javascript mutated service container checkpoint` (unsigned for the same local signing issue)
- `dc4d5d45aee91b1aacf8046555d38e7263881ffa` - `fix: resolve javascript spread service containers` (unsigned for the same local signing issue)
- `f1f5478cf9499857dcddf320b2a83a1387e86aa6` - `docs: record javascript spread service container checkpoint` (unsigned for the same local signing issue)
- `8e2e64c623b609c6184db4818c39e769b86c40c2` - `fix: resolve javascript rest service containers` (unsigned for the same local signing issue)
- `6c8d655a976f1ef5d8e98c858f77816029d7a8c7` - `docs: record javascript rest service container checkpoint` (unsigned for the same local signing issue)
- `827f8561b80074806d2b1beef40cecef5ca03ebc` - `fix: resolve javascript nested mutated service containers` (unsigned for the same local signing issue)
- `79252e3bd0b88291e379a0f69d2f41f15ccd37e7` - `docs: record javascript nested mutated service container checkpoint` (unsigned for the same local signing issue)
- `9a45cdbe4cf1461cd91306417134c2e1eaa83ee4` - `fix: resolve javascript object factory properties` (unsigned for the same local signing issue)
- `da64f17e60588cbbbe7683b7d81d031c4f9f80e8` - `docs: record javascript object factory property checkpoint` (unsigned for the same local signing issue)
- `6fe7bc9819b7beabf823b6aff7de3574f4f9b6bf` - `fix: resolve javascript inline object factory properties` (unsigned for the same local signing issue)

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
4. Audit remaining class-field and dispatch gaps before making any broad class-field parity claim: deeper framework-specific object construction forms, language-specific class-field edge cases, and deeper callback/HOF language-specific forms.

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

Latest Java unqualified instance-field red proof before `5520f0914`:

```text
taint_interfile_java_unqualified_field count=0 expected=1 errors=0 interfile_lang_count=1
```

Latest Java unqualified instance-field green proof after `5520f0914`:

```text
taint_interfile_java_unqualified_field count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_java_unqualified_field    targets/taint_interfile_java_unqualified_field/App.java    4
```

Latest C#/Kotlin unqualified instance-field red proof before `417d3b881`:

```text
taint_interfile_unqualified_instance_field count=0 expected=2 errors=0 interfile_lang_count=2
```

Latest C#/Kotlin unqualified instance-field green proof after `417d3b881`:

```text
taint_interfile_unqualified_instance_field count=2 expected=2 errors=0 interfile_lang_count=2
rules.taint_interfile_unqualified_instance_field_csharp    targets/taint_interfile_unqualified_instance_field/csharp/App.cs    4
rules.taint_interfile_unqualified_instance_field_kotlin    targets/taint_interfile_unqualified_instance_field/kotlin/app.kt    3
```

Latest static-field red proof before `9ef5934fe`:

```text
java_unqualified count=0 errors=0 interfile_lang_count=1
java_qualified count=0 errors=0 interfile_lang_count=1
csharp_unqualified count=0 errors=0 interfile_lang_count=1
csharp_qualified count=0 errors=0 interfile_lang_count=1
js_static count=0 errors=0 interfile_lang_count=1
```

Latest static-field green proof after `9ef5934fe`:

```text
taint_interfile_static_field count=5 expected=5 errors=0 interfile_lang_count=3
rules.taint_interfile_static_field_csharp    targets/taint_interfile_static_field/csharp_qualified/App.cs    3
rules.taint_interfile_static_field_csharp    targets/taint_interfile_static_field/csharp_unqualified/App.cs    3
rules.taint_interfile_static_field_java    targets/taint_interfile_static_field/java_qualified/App.java    3
rules.taint_interfile_static_field_java    targets/taint_interfile_static_field/java_unqualified/App.java    3
rules.taint_interfile_static_field_js    targets/taint_interfile_static_field/javascript/app.js    4
```

Latest callback green proof after `3f20a1c50`:

```text
taint_interfile_callback count=4 expected=4 errors=0 interfile_lang_count=2
rules.taint_interfile_callback_js    targets/taint_interfile_callback/javascript_return/app.js    3
rules.taint_interfile_callback_js    targets/taint_interfile_callback/javascript_sink/app.js    3
rules.taint_interfile_callback_python    targets/taint_interfile_callback/python_return/app.py    3
rules.taint_interfile_callback_python    targets/taint_interfile_callback/python_sink/app.py    3
```

Callback audit note: the first combined probe reused `source`/`apply` helper names across sibling fixtures and returned no findings because those duplicate relative-module names were ambiguous. The committed regression uses unique helper names to lock the callback behavior itself. Treat callback/import path collision hardening as a separate parity gap.

Latest callback collision red proof before `3b3aa6f15`:

```text
taint_interfile_callback_collision count=0 expected=4 errors=0 interfile_lang_count=2
```

Latest callback collision green proof after `3b3aa6f15`:

```text
taint_interfile_callback_collision count=4 expected=4 errors=0 interfile_lang_count=2
rules.taint_interfile_callback_collision_js    targets/taint_interfile_callback_collision/javascript/first/app.js    3
rules.taint_interfile_callback_collision_js    targets/taint_interfile_callback_collision/javascript/second/app.js    3
rules.taint_interfile_callback_collision_python    targets/taint_interfile_callback_collision/python/first/app.py    3
rules.taint_interfile_callback_collision_python    targets/taint_interfile_callback_collision/python/second/app.py    3
```

Latest typed callback green proof after `164fb8deb`:

```text
taint_interfile_typed_callback count=6 expected=6 errors=0 interfile_lang_count=3
rules.taint_interfile_typed_callback_csharp    targets/taint_interfile_typed_callback/csharp_return/AppReturn.cs    3
rules.taint_interfile_typed_callback_csharp    targets/taint_interfile_typed_callback/csharp_sink/AppSink.cs    3
rules.taint_interfile_typed_callback_java    targets/taint_interfile_typed_callback/java_return/AppReturn.java    3
rules.taint_interfile_typed_callback_java    targets/taint_interfile_typed_callback/java_sink/AppSink.java    3
rules.taint_interfile_typed_callback_kotlin    targets/taint_interfile_typed_callback/kotlin_return/app.kt    2
rules.taint_interfile_typed_callback_kotlin    targets/taint_interfile_typed_callback/kotlin_sink/app.kt    2
```

Latest callback language-matrix green proof after `93d972c3e`:

```text
taint_interfile_callback_language_matrix count=7 expected=7 errors=0 interfile_lang_count=7
rules.taint_interfile_callback_matrix_clojure    targets/taint_interfile_callback_language_matrix/clojure/app.clj    1
rules.taint_interfile_callback_matrix_elixir    targets/taint_interfile_callback_language_matrix/elixir/app.ex    2
rules.taint_interfile_callback_matrix_php    targets/taint_interfile_callback_language_matrix/php/app.php    3
rules.taint_interfile_callback_matrix_ruby    targets/taint_interfile_callback_language_matrix/ruby/app.rb    2
rules.taint_interfile_callback_matrix_rust    targets/taint_interfile_callback_language_matrix/rust/app.rs    1
rules.taint_interfile_callback_matrix_scala    targets/taint_interfile_callback_language_matrix/scala/App.scala    1
rules.taint_interfile_callback_matrix_swift    targets/taint_interfile_callback_language_matrix/swift/app.swift    1
```

Override and multi-level inheritance audit probes after `9ef5934fe`:

```text
java_positive count=1 errors=0 interfile_lang_count=1
java_negative count=0 errors=0 interfile_lang_count=1
python_positive count=1 errors=0 interfile_lang_count=1
python_negative count=0 errors=0 interfile_lang_count=1
js_positive count=1 errors=0 interfile_lang_count=1
js_negative count=0 errors=0 interfile_lang_count=1
java count=1 errors=0 interfile_lang_count=1
python count=1 errors=0 interfile_lang_count=1
js count=1 errors=0 interfile_lang_count=1
```

Latest broad Docker direct scan matrix after `6fe7bc981`:

```text
taint_interfile_js count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_commonjs count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_imported_value count=2 expected=2 errors=0 interfile_lang_count=1
taint_interfile_js_object_method count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_class_field_instance count=2 expected=2 errors=0 interfile_lang_count=2
taint_interfile_constructor_field_instance count=2 expected=2 errors=0 interfile_lang_count=2
taint_interfile_js_constructor_parameter_instance count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_alias count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_reassigned_alias count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_factory count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_factory_local_alias count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_arrow_factory count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_higher_order_factory count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_factory_function_alias count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_service_destructuring count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_nested_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_mutated_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_spread_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_rest_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_nested_mutated_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_object_factory_property count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_inline_object_factory_property count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_branch_alias count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_typescript_parameter_property count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_sanitizer count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_propagator count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_imported_value_package_collision count=2 expected=2 errors=0 interfile_lang_count=2
taint_interfile_java count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_java_unqualified_field count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_unqualified_instance_field count=2 expected=2 errors=0 interfile_lang_count=2
taint_interfile_static_field count=5 expected=5 errors=0 interfile_lang_count=3
taint_interfile_callback count=4 expected=4 errors=0 interfile_lang_count=2
taint_interfile_callback_collision count=4 expected=4 errors=0 interfile_lang_count=2
taint_interfile_typed_callback count=6 expected=6 errors=0 interfile_lang_count=3
taint_interfile_callback_language_matrix count=7 expected=7 errors=0 interfile_lang_count=7
taint_interfile_callback_body_language_matrix count=6 expected=6 errors=0 interfile_lang_count=6
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
matrix_failures=0
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
- Focused direct scans passed for Java unqualified instance-field access through inherited constructor state.
- Focused direct scans passed for C# and Kotlin unqualified instance-field access through constructor/class-init state.
- Focused direct scans passed for Java/C#/JavaScript static class-field state.
- Focused direct scans passed for JavaScript/Python higher-order callback flows where tainted data is passed into a callback and either returned or sunk inside the callback body.
- Focused direct scans passed for JavaScript/Python callback imports with duplicate helper names in sibling directories.
- Focused direct scans passed for Java/Kotlin/C# typed callbacks and delegates.
- Focused direct scans passed for callback-return syntax across Ruby, Scala, Rust, Swift, PHP, Elixir, and Clojure.
- Focused direct scans passed for JavaScript and TypeScript class-field helper instances where `this.source.getInput()` calls a helper object initialized in a class field.
- Focused direct scans passed for JavaScript and TypeScript constructor-assigned helper instances where `this.source = new Source()` is assigned in the constructor.
- Focused direct scans passed for TypeScript constructor parameter properties with typed helper fields.
- Focused direct scans passed for callback-body-sink syntax across Ruby, Scala, Rust, Swift, Elixir, and Clojure.
- Focused direct scans passed for untyped JavaScript constructor-parameter helper instances where `this.source = source` and `new App(new Source())` supplies the helper object.
- Focused direct scans passed for untyped JavaScript constructor-parameter helper aliases where `const helper = new Source(); new App(helper)` supplies the helper object.
- Focused direct scans passed for simple reassigned JavaScript constructor-parameter helper aliases where `const selected = helper; new App(selected)` supplies the helper object.
- Focused direct scans passed for simple factory-returned JavaScript constructor-parameter helpers where `function createSource() { return new Source(); }` feeds `const helper = createSource(); new App(helper)`.
- Focused direct scans passed for factory-local JavaScript constructor-parameter helper aliases where `function createSource() { const helper = new Source(); return helper; }` feeds `const selected = createSource(); new App(selected)`.
- Focused direct scans passed for JavaScript arrow-function constructor factories where `const createSource = () => new Source(); const helper = createSource(); new App(helper)` supplies the helper object.
- Focused direct scans passed for simple JavaScript higher-order constructor factories where `function getFactory() { return createSource; } const helper = getFactory()(); new App(helper)` supplies the helper object.
- Focused direct scans passed for callable JavaScript factory variable aliases where `const factory = getFactory(); const helper = factory(); new App(helper)` supplies the helper object.
- Focused direct scans passed for JavaScript service-container object properties where `const services = { source: new Source() }; new App(services.source)` supplies the helper object.
- Focused direct scans passed for JavaScript destructured service-container properties where `const { source } = services; new App(source)` supplies the helper object.
- Focused direct scans passed for JavaScript nested service-container property paths where `const services = { inputs: { source: new Source() } }; new App(services.inputs.source)` supplies the helper object.
- Focused direct scans passed for JavaScript mutated service-container properties where `const services = {}; services.source = new Source(); new App(services.source)` supplies the helper object.
- Focused direct scans passed for JavaScript spread service-container properties where `const services = { ...base }; new App(services.source)` supplies the helper object.
- Focused direct scans passed for JavaScript rest service-container properties where `const { logger, ...runtimeServices } = services; new App(runtimeServices.source)` supplies the helper object.
- Focused direct scans passed for JavaScript nested mutated service-container aliases where `const nested = services.nested; nested.source = new Source(); new App(services.nested.source)` supplies the helper object.
- Focused direct scans passed for JavaScript object factory properties where `const factories = { source: createSource }; const services = { source: factories.source() }; new App(services.source)` supplies the helper object.
- Focused direct scans passed for JavaScript inline object factory properties where `const factories = { source: () => new Source() }; const services = { source: factories.source() }; new App(services.source)` supplies the helper object.
- Focused direct scans passed for same-class conditional JavaScript constructor-parameter helper aliases where `const selected = condition() ? primary : fallback; new App(selected)` supplies the helper object.
- Direct probes passed for Java/Python/JavaScript override dispatch and multi-level inheritance.
- Broad direct scans passed for `taint_interfile_language_matrix` with 28 findings and `taint_interfile_parser_smoke` with 13 findings.
- `--dataflow-traces` on `taint_interfile_js` produced cross-file source, intermediate variable, and sink trace locations.
- `--dataflow-traces` on the Vue language-matrix fixture produced cross-file source, intermediate variable, and sink trace locations.
- Direct probes showed basic Java, JavaScript, TypeScript, and Python instance dispatch works.
- Direct probes showed field-backed object flows through constructors/methods work for Java, JavaScript, and Python.

Known boundaries:
- `generic` and `regex` are extended non-AST analyzers, not parser-backed target languages. Taint mode now rejects them with a structured `SemgrepError` and CLI help documents that they do not support taint mode.
- Untyped JavaScript constructor-parameter injection for direct constructor calls such as `constructor(source) { this.source = source }` with `new App(new Source())` is now covered. Local helper aliases, simple reassignments, simple factory-returned constructor helpers, factory-local helper aliases, arrow-function factories, simple higher-order factories, callable factory variable aliases, service-container object properties, destructured service-container properties, nested service-container property paths, mutated service-container property assignments, spread service-container properties, rest service-container properties, nested mutated service-container aliases, object factory properties, inline object factory properties, and same-class conditional branch aliases are covered. Broader dependency-injection object-shape variants remain unaudited, including framework-specific injection containers and deeper factory composition.
- PHP callback-body-sink syntax remains blocked by parser/AST lowering for anonymous and arrow functions: current dumps drop lambda parameters and sink call arguments, so the taint engine cannot follow the callback argument into `sink($value)`. PHP callback-return syntax remains covered.
- Do not claim full Semgrep Pro parity until a requirement-by-requirement audit proves it.

Docker-only instruction:
- The user explicitly said to compile in Docker. Do not use local opam/dune builds as the authoritative build gate.

---

## Latest Session Update: Static Fields Green

Static class-field interfile flows now work for Java, C#, and valid JavaScript static field reads.

- `src/engine/Match_tainting_mode.ml` rewrites static field initializers inside synthetic class-initializer bodies as `Class.field = ...` and only passes class-initializer state into static method signature extraction.
- `src/tainting/Dataflow_tainting.ml` maps unqualified enclosed fields to `Class.field` when a static class-field lval is already present in the method environment, falling back to the existing implicit `this.field` behavior otherwise.
- `src/tainting/Taint_signature_extractor.ml` accepts class context for signature extraction so static methods can consume class-initializer state.
- `cli/tests/default/e2e/targets/taint_interfile_static_field/` and `rules/taint_interfile_static_field.yaml` lock Java/C# qualified and unqualified static reads plus JavaScript `StaticSource.value`.

Current targeted scan:

```text
taint_interfile_static_field count=5 expected=5 errors=0 interfile_lang_count=3
rules.taint_interfile_static_field_csharp    targets/taint_interfile_static_field/csharp_qualified/App.cs    3
rules.taint_interfile_static_field_csharp    targets/taint_interfile_static_field/csharp_unqualified/App.cs    3
rules.taint_interfile_static_field_java    targets/taint_interfile_static_field/java_qualified/App.java    3
rules.taint_interfile_static_field_java    targets/taint_interfile_static_field/java_unqualified/App.java    3
rules.taint_interfile_static_field_js    targets/taint_interfile_static_field/javascript/app.js    4
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `taint_interfile_static_field count=5 expected=5 errors=0 interfile_lang_count=3`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Known static-field boundary: JavaScript unqualified `return value` from a static method remains unsupported, which matches JavaScript runtime semantics because class static fields must be read through the class or `this`.

Next resume point: callback coverage and import-path hardening are recorded below; continue with framework-specific object construction gaps or deeper callback/HOF language-specific forms.

---

## Latest Session Update: Callback Coverage Green

Higher-order callback flows are now locked by e2e coverage for JavaScript and Python.

- `cli/tests/default/e2e/rules/taint_interfile_callback.yaml` covers JavaScript and Python callback flows with `options: { interfile: true }`.
- `targets/taint_interfile_callback/javascript_return/` and `python_return/` cover helpers that call a callback with tainted data and return the callback result to a sink.
- `targets/taint_interfile_callback/javascript_sink/` and `python_sink/` cover helpers that call a callback with tainted data and rely on the callback body to call the sink.
- The first fixture intentionally uses unique helper names per variant to isolate callback behavior. The follow-up collision fixture below now covers duplicate relative-module names.

Current targeted scan:

```text
taint_interfile_callback count=4 expected=4 errors=0 interfile_lang_count=2
rules.taint_interfile_callback_js    targets/taint_interfile_callback/javascript_return/app.js    3
rules.taint_interfile_callback_js    targets/taint_interfile_callback/javascript_sink/app.js    3
rules.taint_interfile_callback_python    targets/taint_interfile_callback/python_return/app.py    3
rules.taint_interfile_callback_python    targets/taint_interfile_callback/python_sink/app.py    3
```

Current verification after the coverage checkpoint:

- Docker direct callback scan passes with 4 findings.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue with duplicate relative-module hardening below or move to framework-specific object construction gaps.

---

## Latest Session Update: Callback Import Collisions Green

Callback import resolution now disambiguates same-named relative modules by the caller file path.

- `src/tainting/Graph_from_AST.ml` now computes a caller-relative module path from the import call token and tries that exact suffix before using the existing broad module suffix lookup.
- This keeps existing package/root import behavior as a fallback while resolving sibling directories that both define `source.py`/`higher.py` or `source.js`/`higher.js`.
- `cli/tests/default/e2e/rules/taint_interfile_callback_collision.yaml` and `targets/taint_interfile_callback_collision/` lock the JavaScript and Python duplicate-name regression.

Red proof before the fix:

```text
taint_interfile_callback_collision count=0 expected=4 errors=0 interfile_lang_count=2
```

Green proof after the fix:

```text
taint_interfile_callback_collision count=4 expected=4 errors=0 interfile_lang_count=2
rules.taint_interfile_callback_collision_js    targets/taint_interfile_callback_collision/javascript/first/app.js    3
rules.taint_interfile_callback_collision_js    targets/taint_interfile_callback_collision/javascript/second/app.js    3
rules.taint_interfile_callback_collision_python    targets/taint_interfile_callback_collision/python/first/app.py    3
rules.taint_interfile_callback_collision_python    targets/taint_interfile_callback_collision/python/second/app.py    3
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes, including `taint_interfile_callback_collision count=4`, `taint_interfile_callback count=4`, `taint_interfile_imported_value_package_collision count=2`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: audit framework-specific object construction gaps or deeper callback/HOF forms in Ruby, Scala, Rust, Swift, PHP, Elixir, Clojure, and other configured HOF languages.

---

## Latest Session Update: Typed Callback Coverage Green

Typed callback flows are now locked by e2e coverage for Java, Kotlin, and C#.

- Java coverage uses `Function<String, String>.apply` for callback-return flow and `Consumer<String>.accept` for callback-body-sink flow.
- Kotlin coverage uses function-type parameters with trailing lambda call sites for both return and sink forms.
- C# coverage uses `Func<string, string>.Invoke` and `Action<string>.Invoke` delegate forms.

Current targeted scan:

```text
taint_interfile_typed_callback count=6 expected=6 errors=0 interfile_lang_count=3
rules.taint_interfile_typed_callback_csharp    targets/taint_interfile_typed_callback/csharp_return/AppReturn.cs    3
rules.taint_interfile_typed_callback_csharp    targets/taint_interfile_typed_callback/csharp_sink/AppSink.cs    3
rules.taint_interfile_typed_callback_java    targets/taint_interfile_typed_callback/java_return/AppReturn.java    3
rules.taint_interfile_typed_callback_java    targets/taint_interfile_typed_callback/java_sink/AppSink.java    3
rules.taint_interfile_typed_callback_kotlin    targets/taint_interfile_typed_callback/kotlin_return/app.kt    2
rules.taint_interfile_typed_callback_kotlin    targets/taint_interfile_typed_callback/kotlin_sink/app.kt    2
```

Current verification after the coverage checkpoint:

- Docker direct typed callback scan passes with 6 findings.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: move to framework-specific object construction gaps, language-specific class-field edge cases, or callback-body-sink variants for the broader callback language matrix.

---

## Latest Session Update: Callback Language Matrix Green

Callback-return flows are now locked across seven additional languages.

- `cli/tests/default/e2e/rules/taint_interfile_callback_language_matrix.yaml` covers Ruby, Scala, Rust, Swift, PHP, Elixir, and Clojure.
- The fixture uses each language's ordinary callback syntax: Ruby proc `.call`, Scala/Rust/Swift function values, PHP closure calls, Elixir `fn`, and Clojure `fn`.
- This complements the JavaScript/Python callback fixtures and the Java/Kotlin/C# typed callback matrix.

Current targeted scan:

```text
taint_interfile_callback_language_matrix count=7 expected=7 errors=0 interfile_lang_count=7
rules.taint_interfile_callback_matrix_clojure    targets/taint_interfile_callback_language_matrix/clojure/app.clj    1
rules.taint_interfile_callback_matrix_elixir    targets/taint_interfile_callback_language_matrix/elixir/app.ex    2
rules.taint_interfile_callback_matrix_php    targets/taint_interfile_callback_language_matrix/php/app.php    3
rules.taint_interfile_callback_matrix_ruby    targets/taint_interfile_callback_language_matrix/ruby/app.rb    2
rules.taint_interfile_callback_matrix_rust    targets/taint_interfile_callback_language_matrix/rust/app.rs    1
rules.taint_interfile_callback_matrix_scala    targets/taint_interfile_callback_language_matrix/scala/App.scala    1
rules.taint_interfile_callback_matrix_swift    targets/taint_interfile_callback_language_matrix/swift/app.swift    1
```

Current verification after the coverage checkpoint:

- Docker direct callback language-matrix scan passes with 7 findings.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: audit framework-specific object construction gaps, language-specific class-field edge cases, or callback-body-sink variants for these broader callback languages.

---

## Latest Session Update: Class Field Helper Instances Green

JavaScript and TypeScript class-field helper instances now work when a method calls through `this.<field>.<method>()`.

- `src/tainting/Graph_from_AST.ml` now resolves nested receiver calls such as `this.source.getInput()` by mapping the instance field to the helper class through object-initialization mappings or type metadata.
- `src/tainting/Dataflow_tainting.ml` now consumes taint signatures for nested `this` receiver calls by using the call-graph edge at the method token. This complements the existing `obj.method()` and `this.method()` lookup paths.
- `cli/tests/default/e2e/rules/taint_interfile_class_field_instance.yaml` and `targets/taint_interfile_class_field_instance/` lock the JavaScript and TypeScript class-field helper regression.

Red proof before the fix:

```text
taint_interfile_class_field_instance count=0 expected=2 errors=0 interfile_lang_count=2
```

Green proof after the fix:

```text
taint_interfile_class_field_instance count=2 expected=2 errors=0 interfile_lang_count=2
rules.taint_interfile_class_field_instance_js    targets/taint_interfile_class_field_instance/javascript/app.js    7
rules.taint_interfile_class_field_instance_ts    targets/taint_interfile_class_field_instance/typescript/app.ts    7
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes, including `taint_interfile_class_field_instance count=2`, `taint_interfile_static_field count=5`, `taint_interfile_callback_collision count=4`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing deeper framework-specific object construction forms, language-specific class-field edge cases, or callback-body-sink variants for the broader callback language matrix.

---

## Latest Session Update: Constructor-Assigned Helper Instances Green

JavaScript and TypeScript constructor-assigned helper instances now work when constructors assign `this.<field> = new Helper()` and later methods call through that field.

- `src/tainting/Object_initialization.ml` now records `this.field = new ClassName()` and `self.field = ClassName()` object-initialization mappings, complementing existing local-variable and class-field initializer mappings.
- This reuses the nested `this.<field>.<method>()` call graph and signature lookup support from the class-field checkpoint above.
- `cli/tests/default/e2e/rules/taint_interfile_constructor_field_instance.yaml` and `targets/taint_interfile_constructor_field_instance/` lock the JavaScript and TypeScript constructor-assignment regression.

Red proof before the fix:

```text
taint_interfile_constructor_field_instance count=0 expected=2 errors=0 interfile_lang_count=2
```

Green proof after the fix:

```text
taint_interfile_constructor_field_instance count=2 expected=2 errors=0 interfile_lang_count=2
rules.taint_interfile_constructor_field_instance_js    targets/taint_interfile_constructor_field_instance/javascript/app.js    9
rules.taint_interfile_constructor_field_instance_ts    targets/taint_interfile_constructor_field_instance/typescript/app.ts    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes, including `taint_interfile_constructor_field_instance count=2`, `taint_interfile_class_field_instance count=2`, `taint_interfile_static_field count=5`, `taint_interfile_callback_collision count=4`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing deeper dependency-injection forms such as constructor parameters assigned to fields, language-specific class-field edge cases, or callback-body-sink variants for the broader callback language matrix.

---

## Latest Session Update: TypeScript Parameter Properties Green

TypeScript constructor parameter properties now work when a typed parameter property is later used through `this.<field>.<method>()`.

- `src/tainting/Object_initialization.ml` now records parameter-property fields with class types from constructor parameters that carry visibility or readonly-style attributes.
- This covers syntax such as `constructor(private source: Source) {}` without requiring a separate field declaration or explicit constructor assignment.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_parameter_property.yaml` and `targets/taint_interfile_typescript_parameter_property/` lock the TypeScript parameter-property regression.

Red proof before the fix:

```text
taint_interfile_typescript_parameter_property count=0 expected=1 errors=0 interfile_lang_count=1
```

Green proof after the fix:

```text
taint_interfile_typescript_parameter_property count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_parameter_property    targets/taint_interfile_typescript_parameter_property/app.ts    7
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes, including `taint_interfile_typescript_parameter_property count=1`, `taint_interfile_constructor_field_instance count=2`, `taint_interfile_class_field_instance count=2`, `taint_interfile_static_field count=5`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Follow-up note: this covers typed TypeScript parameter properties. Untyped JavaScript constructor arguments are handled by the later JavaScript constructor-parameter checkpoint.

Next resume point: audit callback-body-sink variants for the broader callback language matrix or more language-specific class-field edge cases.

---

## Latest Session Update: Callback Body Language Matrix Green

Callback-body-sink flows are now locked across six additional languages.

- `cli/tests/default/e2e/rules/taint_interfile_callback_body_language_matrix.yaml` covers Ruby, Scala, Rust, Swift, Elixir, and Clojure.
- The fixture uses each language's ordinary callback-body sink syntax: Ruby proc `.call`, Scala/Rust/Swift function values, Elixir `fn`, and Clojure `fn`.
- This complements the JavaScript/Python callback-body-sink fixtures and the callback-return language matrix.

Current targeted scan:

```text
taint_interfile_callback_body_language_matrix count=6 expected=6 errors=0 interfile_lang_count=6
rules.taint_interfile_callback_body_matrix_clojure    targets/taint_interfile_callback_body_language_matrix/clojure/app.clj    1
rules.taint_interfile_callback_body_matrix_elixir    targets/taint_interfile_callback_body_language_matrix/elixir/app.ex    2
rules.taint_interfile_callback_body_matrix_ruby    targets/taint_interfile_callback_body_language_matrix/ruby/app.rb    2
rules.taint_interfile_callback_body_matrix_rust    targets/taint_interfile_callback_body_language_matrix/rust/app.rs    1
rules.taint_interfile_callback_body_matrix_scala    targets/taint_interfile_callback_body_language_matrix/scala/App.scala    1
rules.taint_interfile_callback_body_matrix_swift    targets/taint_interfile_callback_body_language_matrix/swift/app.swift    1
```

Current verification after the coverage checkpoint:

- Docker direct callback-body language-matrix scan passes with 6 findings.
- Full direct regression matrix passes, including `taint_interfile_callback_body_language_matrix count=6`, `taint_interfile_callback_language_matrix count=7`, `taint_interfile_typed_callback count=6`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: PHP callback-body-sink syntax is not included because current PHP AST dumps for `function($value) { sink($value); }` and `fn($value) => sink($value)` drop both lambda parameters and sink call arguments. PHP callback-return syntax remains covered by `taint_interfile_callback_language_matrix`.

Next resume point: continue auditing language-specific class-field edge cases or investigate the PHP parser lowering gap separately from taint propagation.

---

## Latest Session Update: JavaScript Mutated Service Containers Green

Untyped JavaScript constructor-parameter helper instances now work when a constructor stores a parameter into an instance field and a call site supplies a helper instance directly, through a local alias, through a simple reassigned alias, through a simple factory function, through a factory-local helper alias, through a variable-assigned arrow factory, through a simple higher-order factory, through a callable factory variable alias, through a service-container object property, through a destructured service-container property, through a nested service-container property path, through a mutated service-container property assignment, or through a same-class conditional branch alias.

- `src/tainting/Object_initialization.ml` records constructor assignments like `this.source = source` by parameter index.
- When the same class is instantiated with `new App(new Source())`, object initialization now maps the stored field to the argument's constructor class.
- When the constructor argument is an identifier such as `helper`, object initialization now reuses the existing `helper -> Source` object mapping from `const helper = new Source()`.
- Simple object aliases now propagate mappings forward, so `const selected = helper; new App(selected)` keeps the `selected -> Source` shape.
- Simple factory functions that directly return a constructor expression now record a return class, so `const helper = createSource(); new App(helper)` keeps the `helper -> Source` shape when `createSource()` returns `new Source()`.
- Factory return analysis now tracks local constructor aliases before recording a return class, so `function createSource() { const helper = new Source(); return helper; }` keeps the `createSource() -> Source` shape.
- Variable-assigned arrow functions now participate in the function-return prepass, so `const createSource = () => new Source(); const helper = createSource(); new App(helper)` keeps the `helper -> Source` shape.
- Functions that return another known factory are now tracked as function aliases, so `function getFactory() { return createSource; } const helper = getFactory()(); new App(helper)` keeps the `helper -> Source` shape.
- Callable variable aliases now participate in factory resolution, so `const factory = getFactory(); const helper = factory(); new App(helper)` keeps the `helper -> Source` shape.
- Object literal fields now record service property shapes, so `const services = { source: new Source() }; new App(services.source)` keeps the `services.source -> Source` shape.
- Destructuring declarations now reuse recorded service property shapes, so `const { source } = services; new App(source)` keeps the `source -> Source` shape.
- Nested object literal fields now record full service property paths, so `const services = { inputs: { source: new Source() } }; new App(services.inputs.source)` keeps the `services.inputs.source -> Source` shape.
- Assignments into object properties now record service property shapes, so `const services = {}; services.source = new Source(); new App(services.source)` keeps the `services.source -> Source` shape.
- Same-class conditional expressions now resolve object shapes recursively, so `const selected = condition() ? primary : fallback; new App(selected)` keeps the `selected -> Source` shape when both branches resolve to `Source`.
- This reuses the existing nested `this.<field>.<method>()` call graph and taint-signature lookup support.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_instance.yaml` and `targets/taint_interfile_js_constructor_parameter_instance/` lock the regression.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_alias.yaml` and `targets/taint_interfile_js_constructor_parameter_alias/` lock the local-alias regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_reassigned_alias.yaml` and `targets/taint_interfile_js_constructor_parameter_reassigned_alias/` lock the reassigned-alias regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_factory.yaml` and `targets/taint_interfile_js_constructor_parameter_factory/` lock the simple factory-return regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_factory_local_alias.yaml` and `targets/taint_interfile_js_constructor_parameter_factory_local_alias/` lock the factory-local-alias regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_arrow_factory.yaml` and `targets/taint_interfile_js_constructor_parameter_arrow_factory/` lock the variable-assigned arrow-factory regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_higher_order_factory.yaml` and `targets/taint_interfile_js_constructor_parameter_higher_order_factory/` lock the simple higher-order factory regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_factory_function_alias.yaml` and `targets/taint_interfile_js_constructor_parameter_factory_function_alias/` lock the callable factory variable-alias regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_service_container/` lock the service-container object-property regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_service_destructuring.yaml` and `targets/taint_interfile_js_constructor_parameter_service_destructuring/` lock the destructured service-container regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_nested_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_nested_service_container/` lock the nested service-container property-path regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_mutated_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_mutated_service_container/` lock the mutated service-container assignment regression in isolation.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_branch_alias.yaml` and `targets/taint_interfile_js_constructor_parameter_branch_alias/` lock the same-class conditional branch regression in isolation.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_instance count=0 expected=1 errors=0 interfile_lang_count=1
```

Green proof after the fix:

```text
taint_interfile_js_constructor_parameter_instance count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_instance    targets/taint_interfile_js_constructor_parameter_instance/app.js    9
```

Alias red proof before the alias fix:

```text
taint_interfile_js_constructor_parameter_alias count=0 expected=1 errors=0 interfile_lang_count=1
```

Alias green proof after the alias fix:

```text
taint_interfile_js_constructor_parameter_alias count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_alias    targets/taint_interfile_js_constructor_parameter_alias/app.js    9
```

Reassigned-alias red proof before the alias-propagation fix:

```text
taint_interfile_js_constructor_parameter_reassigned_alias count=0 expected=1 errors=0 interfile_lang_count=1
```

Reassigned-alias green proof after the alias-propagation fix:

```text
taint_interfile_js_constructor_parameter_reassigned_alias count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_reassigned_alias    targets/taint_interfile_js_constructor_parameter_reassigned_alias/app.js    9
```

Factory red proof before the factory-return fix:

```text
taint_interfile_js_constructor_parameter_factory count=0 expected=1 errors=0 interfile_lang_count=1
```

Factory green proof after the factory-return fix:

```text
taint_interfile_js_constructor_parameter_factory count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_factory    targets/taint_interfile_js_constructor_parameter_factory/app.js    9
```

Factory-local-alias red proof before the local factory mapping fix:

```text
taint_interfile_js_constructor_parameter_factory_local_alias count=0 expected=1 errors=0 interfile_lang_count=1
```

Factory-local-alias green proof after the local factory mapping fix:

```text
taint_interfile_js_constructor_parameter_factory_local_alias count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_factory_local_alias    targets/taint_interfile_js_constructor_parameter_factory_local_alias/app.js    9
```

Arrow-factory red proof before the lambda factory fix:

```text
taint_interfile_js_constructor_parameter_arrow_factory count=0 expected=1 errors=0 interfile_lang_count=1
```

Arrow-factory green proof after the lambda factory fix:

```text
taint_interfile_js_constructor_parameter_arrow_factory count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_arrow_factory    targets/taint_interfile_js_constructor_parameter_arrow_factory/app.js    9
```

Higher-order factory red proof before the function-alias fix:

```text
taint_interfile_js_constructor_parameter_higher_order_factory count=0 expected=1 errors=0 interfile_lang_count=1
```

Higher-order factory green proof after the function-alias fix:

```text
taint_interfile_js_constructor_parameter_higher_order_factory count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_higher_order_factory    targets/taint_interfile_js_constructor_parameter_higher_order_factory/app.js    9
```

Factory function-alias red proof before the callable-alias fix:

```text
taint_interfile_js_constructor_parameter_factory_function_alias count=0 expected=1 errors=0 interfile_lang_count=1
```

Factory function-alias green proof after the callable-alias fix:

```text
taint_interfile_js_constructor_parameter_factory_function_alias count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_factory_function_alias    targets/taint_interfile_js_constructor_parameter_factory_function_alias/app.js    9
```

Service-container red proof before the object-property shape fix:

```text
taint_interfile_js_constructor_parameter_service_container count=0 expected=1 errors=0 interfile_lang_count=1
```

Service-container green proof after the object-property shape fix:

```text
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_service_container    targets/taint_interfile_js_constructor_parameter_service_container/app.js    9
```

Service-destructuring red proof before the destructured property shape fix:

```text
taint_interfile_js_constructor_parameter_service_destructuring count=0 expected=1 errors=0 interfile_lang_count=1
```

Service-destructuring green proof after the destructured property shape fix:

```text
taint_interfile_js_constructor_parameter_service_destructuring count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_service_destructuring    targets/taint_interfile_js_constructor_parameter_service_destructuring/app.js    9
```

Nested service-container red proof before the nested property-path fix:

```text
taint_interfile_js_constructor_parameter_nested_service_container count=0 expected=1 errors=0 interfile_lang_count=1
```

Nested service-container green proof after the nested property-path fix:

```text
taint_interfile_js_constructor_parameter_nested_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_nested_service_container    targets/taint_interfile_js_constructor_parameter_nested_service_container/app.js    9
```

Mutated service-container red proof before the object-property assignment fix:

```text
taint_interfile_js_constructor_parameter_mutated_service_container count=0 expected=1 errors=0 interfile_lang_count=1
```

Mutated service-container green proof after the object-property assignment fix:

```text
taint_interfile_js_constructor_parameter_mutated_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_mutated_service_container    targets/taint_interfile_js_constructor_parameter_mutated_service_container/app.js    9
```

Branch-alias red proof before the conditional object-shape fix:

```text
taint_interfile_js_constructor_parameter_branch_alias count=0 expected=1 errors=0 interfile_lang_count=1
```

Branch-alias green proof after the conditional object-shape fix:

```text
taint_interfile_js_constructor_parameter_branch_alias count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_branch_alias    targets/taint_interfile_js_constructor_parameter_branch_alias/app.js    9
```

Spread service-container red proof before the object-spread shape fix:

```text
taint_interfile_js_constructor_parameter_spread_service_container count=0 expected=1 errors=0 interfile_lang_count=1
```

Spread service-container green proof after the object-spread shape fix:

```text
taint_interfile_js_constructor_parameter_spread_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_spread_service_container    targets/taint_interfile_js_constructor_parameter_spread_service_container/app.js    9
```

Rest service-container red proof before the object-rest shape fix:

```text
taint_interfile_js_constructor_parameter_rest_service_container count=0 expected=1 errors=0 interfile_lang_count=1
```

Rest service-container green proof after the object-rest shape fix:

```text
taint_interfile_js_constructor_parameter_rest_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_rest_service_container    targets/taint_interfile_js_constructor_parameter_rest_service_container/app.js    9
```

Nested mutated service-container red proof before the nested object-alias fix:

```text
taint_interfile_js_constructor_parameter_nested_mutated_service_container count=0 expected=1 errors=0 interfile_lang_count=1
```

Nested mutated service-container green proof after the nested object-alias fix:

```text
taint_interfile_js_constructor_parameter_nested_mutated_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_nested_mutated_service_container    targets/taint_interfile_js_constructor_parameter_nested_mutated_service_container/app.js    9
```

Object factory-property red proof before the property-function mapping fix:

```text
taint_interfile_js_constructor_parameter_object_factory_property count=0 expected=1 errors=0 interfile_lang_count=1
```

Object factory-property green proof after the property-function mapping fix:

```text
taint_interfile_js_constructor_parameter_object_factory_property count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_object_factory_property    targets/taint_interfile_js_constructor_parameter_object_factory_property/app.js    9
```

Inline object factory-property red proof before the inline property-factory mapping fix:

```text
taint_interfile_js_constructor_parameter_inline_object_factory_property count=0 expected=1 errors=0 interfile_lang_count=1
```

Inline object factory-property green proof after the inline property-factory mapping fix:

```text
taint_interfile_js_constructor_parameter_inline_object_factory_property count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_inline_object_factory_property    targets/taint_interfile_js_constructor_parameter_inline_object_factory_property/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes, including `taint_interfile_js_constructor_parameter_instance count=1`, `taint_interfile_js_constructor_parameter_alias count=1`, `taint_interfile_js_constructor_parameter_reassigned_alias count=1`, `taint_interfile_js_constructor_parameter_factory count=1`, `taint_interfile_js_constructor_parameter_factory_local_alias count=1`, `taint_interfile_js_constructor_parameter_arrow_factory count=1`, `taint_interfile_js_constructor_parameter_higher_order_factory count=1`, `taint_interfile_js_constructor_parameter_factory_function_alias count=1`, `taint_interfile_js_constructor_parameter_service_container count=1`, `taint_interfile_js_constructor_parameter_service_destructuring count=1`, `taint_interfile_js_constructor_parameter_nested_service_container count=1`, `taint_interfile_js_constructor_parameter_mutated_service_container count=1`, `taint_interfile_js_constructor_parameter_spread_service_container count=1`, `taint_interfile_js_constructor_parameter_rest_service_container count=1`, `taint_interfile_js_constructor_parameter_nested_mutated_service_container count=1`, `taint_interfile_js_constructor_parameter_object_factory_property count=1`, `taint_interfile_js_constructor_parameter_inline_object_factory_property count=1`, `taint_interfile_js_constructor_parameter_branch_alias count=1`, `taint_interfile_constructor_field_instance count=2`, `taint_interfile_class_field_instance count=2`, `taint_interfile_callback_body_language_matrix count=6`, `taint_interfile_language_matrix count=28`, `taint_interfile_parser_smoke count=13`, and `matrix_failures=0`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: direct constructor-argument object shapes, simple local helper aliases, simple alias reassignments, simple factory-returned constructor helpers, factory-local helper aliases, variable-assigned arrow factories, simple higher-order factories, callable factory variable aliases, service-container object properties, destructured service-container properties, nested service-container property paths, mutated service-container property assignments, object-spread service containers, object-rest service containers, nested mutated service-container aliases, object factory properties, inline object factory properties, and same-class conditional branch aliases are covered. Broader dependency-injection forms remain unaudited, including framework/container injection and deeper factory composition.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and deeper factory composition.

---

## Latest Session Update: JavaScript Inline Object Factory Properties Green

JavaScript inline object factory properties now preserve object-shape information when a factory stored directly as an object property returns a helper instance.

- `src/tainting/Object_initialization.ml` records object properties whose inline lambda bodies return known helper classes and consults those mappings when resolving calls such as `factories.source()`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_inline_object_factory_property.yaml` and `targets/taint_interfile_js_constructor_parameter_inline_object_factory_property/` lock the regression.
- Focused direct scan passed for `const factories = { source: () => new Source() }; const services = { source: factories.source() }; new App(services.source)`.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_inline_object_factory_property count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_inline_object_factory_property    targets/taint_interfile_js_constructor_parameter_inline_object_factory_property/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new inline object factory-property fixture, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and deeper factory composition.

---

## Latest Session Update: JavaScript Object Factory Properties Green

JavaScript object factory properties now preserve object-shape information when a service object calls a factory stored in another object property.

- `src/tainting/Object_initialization.ml` records object properties that point to known factory functions and consults those mappings when resolving calls such as `factories.source()`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_object_factory_property.yaml` and `targets/taint_interfile_js_constructor_parameter_object_factory_property/` lock the regression.
- Focused direct scan passed for `const factories = { source: createSource }; const services = { source: factories.source() }; new App(services.source)`.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_object_factory_property count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_object_factory_property    targets/taint_interfile_js_constructor_parameter_object_factory_property/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new object factory-property fixture, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and deeper factory composition.

---

## Latest Session Update: JavaScript Nested Mutated Service Containers Green

JavaScript nested mutated service containers now preserve object-shape information when a nested service object is aliased before mutation, then later read through the original nested path.

- `src/tainting/Object_initialization.ml` records object-property aliases such as `const nested = services.nested` and mirrors later writes through `nested.source` onto `services.nested.source`.
- Alias resolution follows simple alias chains and guards against cycles.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_nested_mutated_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_nested_mutated_service_container/` lock the regression.
- Focused direct scan passed for `const nested = services.nested; nested.source = new Source(); new App(services.nested.source)`.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_nested_mutated_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_nested_mutated_service_container    targets/taint_interfile_js_constructor_parameter_nested_mutated_service_container/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new nested-mutated service-container fixture, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and more complex factory composition.

---

## Latest Session Update: JavaScript Rest Service Containers Green

JavaScript service-container rest destructuring now keeps object-shape information when a call site passes a helper from `const { logger, ...runtimeServices } = services` into a constructor.

- `src/tainting/Object_initialization.ml` copies known source object property shapes onto rest destructuring variables while excluding explicitly destructured top-level fields.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_rest_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_rest_service_container/` lock the regression.
- Focused direct scan passed for a JavaScript rest service-container property where `const { logger, ...runtimeServices } = services; new App(runtimeServices.source)` supplies the helper object.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_rest_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_rest_service_container    targets/taint_interfile_js_constructor_parameter_rest_service_container/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new rest service-container fixture, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and more complex factory composition.

---

## Latest Session Update: JavaScript Spread Service Containers Green

JavaScript service-container spread copies now keep object-shape information when a call site passes a helper from `const services = { ...base }` into a constructor.

- `src/tainting/Object_initialization.ml` copies known service property shapes for object spread fields, so `services.source` inherits the `base.source -> Source` mapping.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_spread_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_spread_service_container/` lock the regression.
- Focused direct scan passed for a JavaScript spread service-container property where `const base = { source: new Source() }; const services = { ...base }; new App(services.source)` supplies the helper object.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_spread_service_container count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_spread_service_container    targets/taint_interfile_js_constructor_parameter_spread_service_container/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new spread service-container fixture, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and more complex factory composition.

---

## Latest Session Update: C# and Kotlin Fields Green

C# and Kotlin field-backed interfile flows now work when a method returns an unqualified field name.

- `src/tainting/Dataflow_tainting.ml` treats Java, C#, and Kotlin `EnclosedVar` lvalues as implicit `this.<field>` lvalues and recognizes synthetic class initializers as constructor-like state producers.
- `src/tainting/Taint_signature_extractor.ml` seeds implicit receiver method properties for the same three languages.
- `src/engine/Match_tainting_mode.ml` creates synthetic class-initializer signatures from class field initializers and init blocks.
- `src/tainting/Graph_from_AST.ml` resolves constructor calls to explicit lineage constructors first, then falls back to `Class:<name>` initializer nodes when no explicit constructor exists.
- `cli/tests/default/e2e/targets/taint_interfile_unqualified_instance_field/` and `rules/taint_interfile_unqualified_instance_field.yaml` lock the C#/Kotlin regression.

Current targeted scan:

```text
taint_interfile_unqualified_instance_field count=2 expected=2 errors=0 interfile_lang_count=2
rules.taint_interfile_unqualified_instance_field_csharp    targets/taint_interfile_unqualified_instance_field/csharp/App.cs    4
rules.taint_interfile_unqualified_instance_field_kotlin    targets/taint_interfile_unqualified_instance_field/kotlin/app.kt    3
```

Current verification after the fix:

- Docker `make core` passes.
- Direct C#/Kotlin unqualified instance-field scan returns both expected findings.
- Full direct regression matrix passes, including inherited constructors, Java unqualified fields, the 28-finding language matrix, and the 13-finding parser smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Commit/signing note: `417d3b881d99608389b6de341746b66a972134b1` was pushed over HTTPS. It is unsigned because the configured 1Password SSH signer failed twice with `failed to fill whole buffer`, direct SSH signing with `~/.ssh/id_ed25519` required an unavailable passphrase, and SSH push was blocked by the local agent.

Next resume point: continue the class/object parity audit with static fields, overridden methods, multi-level inheritance, and higher-order callback flows.

---

## Latest Session Update: Java Unqualified Fields Green

Java field-backed interfile flows now work when an inherited method returns an unqualified field name instead of `this.<field>`.

- `src/tainting/Dataflow_tainting.ml` canonicalizes Java `EnclosedVar` field lvalues to implicit `this.<field>` during local taint propagation.
- `src/tainting/Taint_signature_extractor.ml` seeds method properties for unqualified Java fields by synthesizing the same implicit receiver shape in signatures.
- `src/engine/Match_tainting_mode.ml` passes the target language into signature extraction.
- `cli/tests/default/e2e/targets/taint_interfile_java_unqualified_field/` and `rules/taint_interfile_java_unqualified_field.yaml` lock the regression.

Current targeted scan:

```text
taint_interfile_java_unqualified_field count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_java_unqualified_field    targets/taint_interfile_java_unqualified_field/App.java    4
```

Current verification after the fix:

- Docker `make core` passes.
- Direct Java unqualified field scan returns the expected finding.
- Focused direct regression matrix passes, including `taint_interfile_java_unqualified_field count=1 expected=1 errors=0 interfile_lang_count=1`, `taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28`, and `taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: audit adjacent class-field and dispatch parity gaps, especially C#/Kotlin unqualified instance fields, static fields, overrides, and higher-order callback flows.

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
