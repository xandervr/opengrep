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
- TypeScript decorated property injection now resolves when a static provider binding such as `container.bind("source").to(Source)` is consumed through an untyped `@Inject("source")` class field.
- TypeScript decorated constructor-parameter injection now resolves when `constructor(@Inject("source") source) { this.source = source }` consumes a static provider binding.
- TypeScript decorated constructor-parameter direct injection now resolves when `constructor(@Inject("source") source) { sink(source.getInput()) }` consumes a static provider binding without assigning the parameter to a field.
- TypeScript decorated metadata injection now resolves when keyless `@Inject()` decorators rely on TypeScript class metadata for decorated fields, direct constructor parameters, and constructor parameters assigned to fields.
- TypeScript injectable constructor metadata now resolves when DI-decorated classes such as `@Injectable()` use typed constructor parameters without explicit `@Inject()` keys or call-site arguments.
- JavaScript dynamic service-container keys now resolve when the same unknown key variable is used for both provider write and consumer read, covering bracket assignment, `Map`-style `set`/`get`, and provider `bind(...).to(...)` plus `get(...)`.
- JavaScript dynamic template-expression service-container keys now resolve when the same non-static template expression is used on both provider and consumer sides.
- JavaScript provider method aliases now resolve through `asClass`, `asValue`, and `asFunction`, matching the existing class/value/factory provider semantics.
- JavaScript registration-map containers now resolve `register({ source: asClass(Source) })`, `asValue(new Source())`, and `asFunction(() => new Source())` provider specs consumed through `resolve("source")`.
- JavaScript provider alias containers now resolve `useExisting`, `toService`, and `aliasTo` provider aliases when the aliased provider key already has a class/value/factory binding.
- JavaScript and TypeScript async provider containers now resolve async dynamic factories consumed through `await container.getAsync("source")` and `await container.resolveAsync("source")`.
- JavaScript hierarchical provider containers now resolve parent bindings through child/scope containers created by `createChild()`, `createChildContainer()`, and `createScope()`.
- JavaScript provider lifecycle/scoping chains now resolve provider bindings wrapped by methods such as `inSingletonScope()`, `singleton()`, and lifecycle modifiers on registration-map provider specs.
- JavaScript provider-object arrays now resolve registration entries like `{ provide: "source", useClass: Source }`, `{ token: "source", useValue: new Source() }`, and `{ name: "source", useFactory: () => new Source() }`.
- TypeScript provider metadata containers now resolve `providers: [...]` arrays in decorator metadata and bootstrap/module call metadata, covering object providers that bind untyped `@Inject("source")` constructor parameters through `useClass`, `useFactory`, and `useValue`.
- TypeScript provider metadata aliases now resolve same-file and imported provider arrays passed as `providers: providerList` in decorator/bootstrap metadata.
- TypeScript class-token provider metadata now resolves typed constructor metadata through provider tokens such as `{ provide: TokenClass, useClass: TokenImpl }`, including direct, same-file provider-list alias, and imported provider-list alias forms.
- TypeScript provider metadata spreads now resolve `providers: [...providerList]` in direct decorator metadata, metadata objects passed to bootstrap calls, and imported provider-list metadata.
- TypeScript nested provider arrays now resolve provider objects inside nested `providers` arrays for direct metadata, same-file provider-list aliases, and imported provider-list aliases.
- TypeScript provider class shorthand metadata now resolves `providers: [SourceClass]` entries in direct metadata, same-file provider-list aliases, and imported provider-list aliases, including explicit `@Inject(SourceClass)` constructor parameters.
- JavaScript provider tuple arrays now resolve registration entries like `register([["source", asClass(Source)]])`, `asFunction(() => new Source())`, and `asValue(new Source())`, and the map-service coverage now includes constructor tuples such as `new Map([["source", new Source()]])`.
- JavaScript two-argument provider spec registrations now resolve calls like `register("source", asClass(Source))`, `asFunction(() => new Source())`, and `asValue(new Source())`; the provider-spec handling is shared by ordinary object-property value mappings.
- TypeScript `forwardRef(() => Class)` wrappers now resolve for explicit `@Inject(forwardRef(...))` constructor parameters, provider shorthand metadata entries, and provider-object token metadata.
- JavaScript Inversify-style self bindings now resolve `bind(Source).toSelf()` and lifecycle-wrapped `bind(Source).toSelf().inSingletonScope()` class-token providers.
- TypeScript provider factory dependency metadata now resolves factory providers that return injected dependencies declared through `deps` or `inject`, covering string tokens, class tokens, and Nest-style `inject` arrays.
- TypeScript named provider factory dependency metadata now resolves `useFactory: makeSource` and `useFactory: selectSource` entries when the named function or const lambda returns one of its injected parameters.
- TypeScript optional/location DI metadata decorators now trigger typed constructor metadata for `@Optional()`, `@Self()`, `@SkipSelf()`, and `@Host()` without requiring an explicit `@Inject()` key or class-level `@Injectable()` decorator.
- TypeScript environment provider metadata now resolves provider arrays wrapped by `makeEnvironmentProviders(...)`, including direct, named, and imported wrapper values.
- TypeScript forward provider aliases now resolve `useExisting: forwardRef(() => Token)` provider metadata through later token bindings, including direct, forward-ordered, and imported provider arrays.
- TypeScript registry decorator metadata now resolves TSyringe-style `@registry([...])` provider arrays consumed by lowercase `@inject(...)` constructor parameters, covering `useClass`, `useFactory`, and `useValue` providers.
- JavaScript provider spec registration coverage now includes object provider specs passed as `register("key", { useClass/useFactory/useValue: ... })`.
- Callback-body-sink flows are now covered across Ruby, Scala, Rust, Swift, Elixir, and Clojure syntax forms.
- JavaScript constructor-parameter helper instances now resolve when constructors assign `this.source = source` and a call site passes `new Source()`, a local helper alias, a simple reassigned helper alias, a simple factory-returned helper, a factory-local helper alias, an arrow-function factory helper, a simple higher-order factory, a callable factory variable alias, a service-container object property, string-keyed, constant-keyed, computed-keyed, map-like, template-keyed, dynamic-keyed, dynamic-template-keyed, chained map, container API, provider-binding, provider API alias, provider method alias, provider alias, and registration-map service-container object properties, a service-container factory return, service-container factory aliases, direct destructuring from service-container factory returns, composed service-container factory returns, a destructured service-container property, a nested service-container property path, a mutated service-container property assignment, a spread service-container property, a rest service-container property, a nested mutated service-container alias, an object factory property, an inline object factory property, object factory property aliases, mutated object factory property aliases, or a same-class conditional branch alias into `new App(...)`.

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
- `14093fa83e2ea10735c6d984a34f94c420dbb727` - `fix: resolve javascript object factory property aliases` (unsigned for the same local signing issue)
- `fcfeee3985df57c16b5f1ca8816ae64f471e600f` - `fix: resolve javascript mutated object factory property aliases` (unsigned for the same local signing issue)
- `bb5d5886fa6fb52ea6d78e7af16fc44066691bcf` - `fix: resolve javascript service container factories` (unsigned for the same local signing issue)
- `9df716a6e7e22f5c9b35f36df2c407f528a3d861` - `fix: resolve javascript service container factory aliases` (unsigned for the same local signing issue)
- `430ed81fc07712e14e738153ded27610a427e63d` - `fix: resolve javascript service container factory destructuring` (unsigned for the same local signing issue)
- `a44d6554012073f690c7488c5be14f4b8f5da970` - `fix: resolve javascript composed service container factories` (unsigned for the same local signing issue)
- `f9039b2f1ff266ecd0653c543bbb30bbd673a5c5` - `fix: resolve javascript string keyed service containers` (unsigned for the same local signing issue)
- `0cfd4e3809bda6e01b78e1dc1b993cc03dd510f8` - `fix: resolve javascript constant keyed service containers` (unsigned for the same local signing issue)
- `350237126d02c34c161020410ca014cbbec4ec80` - `fix: resolve javascript computed keyed service containers` (unsigned for the same local signing issue)
- `412def4826a5dafab2d9d277c3ed16b71d8ca5d7` - `fix: resolve javascript map service containers` (unsigned for the same local signing issue)
- `f33f7f57a3aab6dbd09d97c2a0ed4f638c708d99` - `fix: resolve javascript template keyed service containers` (unsigned for the same local signing issue)
- `d5e524a1f1c109c7df8e143951efdf4b2cdf343e` - `fix: resolve javascript chained map service containers` (unsigned for the same local signing issue)
- `057956e4d0127c6d0f04b17d204e258978cd67e6` - `fix: resolve javascript container api service containers` (unsigned for the same local signing issue)
- `85795edefb26c2729b85454c5e0f313591250a96` - `fix: resolve javascript provider service containers` (unsigned for the same local signing issue)
- `41f6fd5df72231bef383165a426e20c360a8a1e9` - `fix: resolve javascript provider api aliases` (unsigned for the same local signing issue)
- `8191e9b4b794fe33b7952199c73aa592f96db5ab` - `fix: resolve typescript decorated property injection` (unsigned for the same local signing issue)
- `aec95cbff3c1b8925aedcef1a267874cf80c098f` - `fix: resolve typescript decorated constructor injection` (unsigned for the same local signing issue)
- `46daf9d1d6bc012747ec876b2e91a3c793cb71ca` - `fix: resolve direct typescript decorated constructor injection` (unsigned for the same local signing issue)
- `389e5bcde` - `fix: resolve javascript dynamic service container keys` (unsigned for the same local signing issue)
- `6af8478a0` - `fix: resolve javascript dynamic template service keys` (unsigned for the same local signing issue)
- `7f1708e24` - `fix: resolve javascript provider method aliases` (unsigned for the same local signing issue)
- `d0d32bdf0` - `fix: resolve javascript registration map containers` (unsigned for the same local signing issue)
- `14c75e4c5` - `fix: resolve typescript decorated metadata injection` (signed)
- `8dd119409` - `fix: resolve typescript injectable constructor metadata` (signed)
- `b4762cf89` - `fix: resolve javascript provider alias containers` (signed)
- `53a4152cc` - `fix: resolve async provider containers` (signed)
- `8ec8add26` - `fix: resolve hierarchical provider containers` (signed)
- `a9ebe2a89` - `fix: resolve provider lifecycle containers` (signed)
- `b6c2dacf3` - `fix: resolve provider object arrays` (signed)
- `b41652c71` - `fix: resolve provider metadata containers` (signed)
- `27f5f2bf` - `fix: resolve provider metadata aliases` (signed)
- `2fca645f2` - `fix: resolve provider token metadata` (signed)
- `04226b045` - `fix: resolve provider metadata spreads` (signed)
- `3dcc43bed` - `fix: resolve nested provider metadata arrays` (signed)
- `241d5fd8b` - `fix: resolve provider shorthand metadata` (signed)
- `9c24e76bb` - `fix: resolve provider tuple arrays` (signed)
- `9bfe35ed3` - `fix: resolve provider spec registrations` (signed)
- `4013b29f8` - `fix: resolve typescript forward ref providers` (signed)
- `8229205c4` - `fix: resolve toself provider containers` (signed)
- `3337b2b81` - `fix: resolve typescript provider factory deps` (signed)
- `5ea01253b` - `fix: resolve typescript named provider factory deps` (signed)
- `38c821cc7` - `fix: resolve typescript optional metadata injection` (signed)
- `caabeef2b` - `fix: resolve typescript environment providers` (signed)
- `41227c142` - `fix: resolve typescript forward provider aliases` (signed)
- `22182d551` - `fix: resolve typescript registry provider metadata` (signed)

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

**Immediate resume point:** continue the broader Semgrep Pro parity audit. Prioritize remaining framework DI forms that are not covered by static provider keys, keyless TypeScript decorator metadata, DI-class constructor type metadata, async `getAsync`/`resolveAsync` provider reads, parent-to-child container aliases, provider lifecycle-chain wrappers, provider-object registration arrays, direct `providers: [...]` metadata, provider-list aliases, class-token provider metadata, provider-list spreads, nested provider arrays, provider class shorthand entries, JavaScript provider tuple arrays, two-argument provider spec registrations, TypeScript `forwardRef(() => Class)` wrappers, Inversify-style `toSelf()` providers, TypeScript provider factory dependency metadata, named TypeScript provider factory dependency metadata, TypeScript optional/location metadata decorators, TypeScript environment-provider wrappers, TypeScript forward provider aliases, or TSyringe-style registry decorator metadata. Good next targets are additional library-specific provider APIs, multi-provider collection injection forms, and tuple-like TypeScript metadata forms that appear in real frameworks. Do not reopen generic/regex unless the user explicitly wants non-Semgrep-Pro behavior for those extended analyzers.

**Next concrete actions:**

1. Re-run the Docker direct scan matrix from Task 4 after any further engine change.
2. Keep `git diff --check` and `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` green.
3. Continue auditing remaining Semgrep Pro parity gaps beyond the covered import/value/export/object/trace/inheritance cases.
4. Audit remaining class-field and dispatch gaps before making any broad class-field parity claim: deeper framework-specific object construction forms, language-specific class-field edge cases, and deeper callback/HOF language-specific forms.

Latest side-effect sanitizer verification:

```text
taint_interfile_python_side_effect_sanitizer count=1 expected=1 errors=0 interfile_lang_count=1
```

Latest async-provider red proof before `53a4152cc`:

```text
async_provider_red count=1 expected=3 errors=0 interfile_lang_count=2
rules.taint_interfile_async_provider_container    targets/taint_interfile_async_provider_container/typescript/app.ts    11
```

Latest async-provider green proof after `53a4152cc`:

```text
async_provider_green count=3 expected=3 errors=0 interfile_lang_count=2
rules.taint_interfile_async_provider_container    targets/taint_interfile_async_provider_container/get_async/app.js    9
rules.taint_interfile_async_provider_container    targets/taint_interfile_async_provider_container/resolve_async/app.js    9
rules.taint_interfile_async_provider_container    targets/taint_interfile_async_provider_container/typescript/app.ts    11
```

Latest broad Docker direct scan matrix after `53a4152cc`:

```text
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest hierarchical-provider red proof before `8ec8add26`:

```text
hierarchical_provider_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest hierarchical-provider green proof after `8ec8add26`:

```text
hierarchical_provider_green count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_hierarchical_provider_container    targets/taint_interfile_hierarchical_provider_container/create_child/app.js    9
rules.taint_interfile_hierarchical_provider_container    targets/taint_interfile_hierarchical_provider_container/create_child_container/app.js    9
rules.taint_interfile_hierarchical_provider_container    targets/taint_interfile_hierarchical_provider_container/create_scope/app.js    9
```

Latest broad Docker direct scan matrix after `8ec8add26`:

```text
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest provider-lifecycle red proof before `a9ebe2a89`:

```text
provider_lifecycle_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest provider-lifecycle green proof after `a9ebe2a89`:

```text
provider_lifecycle_green count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_provider_lifecycle_container    targets/taint_interfile_provider_lifecycle_container/bind_singleton/app.js    9
rules.taint_interfile_provider_lifecycle_container    targets/taint_interfile_provider_lifecycle_container/provide_singleton/app.js    9
rules.taint_interfile_provider_lifecycle_container    targets/taint_interfile_provider_lifecycle_container/register_singleton/app.js    9
```

Latest broad Docker direct scan matrix after `a9ebe2a89`:

```text
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest provider-object-array red proof before `b6c2dacf3`:

```text
provider_object_array_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest provider-object-array green proof after `b6c2dacf3`:

```text
provider_object_array_green count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_provider_object_array_container    targets/taint_interfile_provider_object_array_container/use_class/app.js    9
rules.taint_interfile_provider_object_array_container    targets/taint_interfile_provider_object_array_container/use_factory/app.js    9
rules.taint_interfile_provider_object_array_container    targets/taint_interfile_provider_object_array_container/use_value/app.js    9
```

Latest broad Docker direct scan matrix after `b6c2dacf3`:

```text
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest provider-metadata red proof before `b41652c71`:

```text
provider_metadata_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest provider-metadata green proof after `b41652c71`:

```text
provider_metadata_green count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_provider_metadata_container    targets/taint_interfile_typescript_provider_metadata_container/bootstrap_options/app.ts    11
rules.taint_interfile_typescript_provider_metadata_container    targets/taint_interfile_typescript_provider_metadata_container/create_module/app.ts    15
rules.taint_interfile_typescript_provider_metadata_container    targets/taint_interfile_typescript_provider_metadata_container/decorator_module/app.ts    18
```

Latest broad Docker direct scan matrix after `b41652c71`:

```text
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest provider-metadata-alias red proof before `27f5f2bf`:

```text
provider_metadata_alias_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest provider-metadata-alias green proof after `27f5f2bf`:

```text
provider_metadata_alias_green count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_provider_metadata_alias_container    targets/taint_interfile_typescript_provider_metadata_alias_container/bootstrap_constant/app.ts    15
rules.taint_interfile_typescript_provider_metadata_alias_container    targets/taint_interfile_typescript_provider_metadata_alias_container/decorator_constant/app.ts    20
rules.taint_interfile_typescript_provider_metadata_alias_container    targets/taint_interfile_typescript_provider_metadata_alias_container/imported_constant/app.ts    16
```

Latest broad Docker direct scan matrix after `27f5f2bf`:

```text
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest provider-token-metadata red proof before `2fca645f2`:

```text
provider_token_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest provider-token-metadata green proof after `2fca645f2`:

```text
provider_token_green count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_provider_token_metadata    targets/taint_interfile_typescript_provider_token_metadata/alias_metadata/app.ts    19
rules.taint_interfile_typescript_provider_token_metadata    targets/taint_interfile_typescript_provider_token_metadata/direct_metadata/app.ts    19
rules.taint_interfile_typescript_provider_token_metadata    targets/taint_interfile_typescript_provider_token_metadata/imported_alias_metadata/app.ts    18
```

Latest broad Docker direct scan matrix after `2fca645f2`:

```text
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest provider-metadata-spread red proof before `04226b045`:

```text
provider_metadata_spread_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest provider-metadata-spread green proof after `04226b045`:

```text
provider_metadata_spread_green count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_provider_metadata_spread_container    targets/taint_interfile_typescript_provider_metadata_spread_container/direct_spread/app.ts    20
rules.taint_interfile_typescript_provider_metadata_spread_container    targets/taint_interfile_typescript_provider_metadata_spread_container/imported_spread/app.ts    16
rules.taint_interfile_typescript_provider_metadata_spread_container    targets/taint_interfile_typescript_provider_metadata_spread_container/metadata_spread/app.ts    19
```

Latest broad Docker direct scan matrix after `04226b045`:

```text
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest nested-provider-array red proof before `3dcc43bed`:

```text
provider_nested_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest nested-provider-array green proof after `3dcc43bed`:

```text
provider_nested_green count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_provider_nested_array_metadata    targets/taint_interfile_typescript_provider_nested_array_metadata/alias_nested/app.ts    15
rules.taint_interfile_typescript_provider_nested_array_metadata    targets/taint_interfile_typescript_provider_nested_array_metadata/direct_nested/app.ts    18
rules.taint_interfile_typescript_provider_nested_array_metadata    targets/taint_interfile_typescript_provider_nested_array_metadata/imported_nested/app.ts    16
```

Latest broad Docker direct scan matrix after `3dcc43bed`:

```text
taint_interfile_typescript_provider_nested_array_metadata count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=2 status=0
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=1 status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=1 status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=28 status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=13 status=0
matrix_failures=0
```

Latest provider-shorthand red proof before `241d5fd8b`:

```text
provider_shorthand_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Latest provider-shorthand green proof after `241d5fd8b`:

```text
provider_shorthand_green count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
rules.taint_interfile_typescript_provider_shorthand_metadata    targets/taint_interfile_typescript_provider_shorthand_metadata/alias_shorthand/app.ts    13
rules.taint_interfile_typescript_provider_shorthand_metadata    targets/taint_interfile_typescript_provider_shorthand_metadata/direct_shorthand/app.ts    16
rules.taint_interfile_typescript_provider_shorthand_metadata    targets/taint_interfile_typescript_provider_shorthand_metadata/imported_shorthand/app.ts    17
```

Latest broad Docker direct scan matrix after `241d5fd8b`:

```text
taint_interfile_typescript_provider_shorthand_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_nested_array_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript', 'JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_map_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=['C++', 'C', 'Lisp', 'Scheme', 'Solidity', 'Lua', 'Ruby', 'Dart', 'OCaml', 'Scala', 'Cairo', 'Rust', 'C#', 'Hack', 'Circom', 'Clojure', 'TypeScript', 'PHP', 'Move on Aptos', 'Apex', 'Bash', 'Swift', 'Vue', 'R', 'Kotlin', 'Julia', 'Move on Sui', 'Vb'] status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=['XML', 'Python 3', 'JSON', 'HTML', 'Terraform', 'QL', 'YAML', 'Dockerfile', 'Prometheus Query Language', 'Python 2', 'Vue', 'Jsonnet', 'Protocol Buffers'] status=0
matrix_failures=0
```

Latest provider-tuple red proof before `9c24e76bb`:

```text
provider_tuple_red count=0 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
```

Latest provider-tuple green proof after `9c24e76bb`:

```text
provider_tuple_green count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
rules.taint_interfile_provider_tuple_array_container    targets/taint_interfile_provider_tuple_array_container/tuple_class/app.js    9
rules.taint_interfile_provider_tuple_array_container    targets/taint_interfile_provider_tuple_array_container/tuple_factory/app.js    9
rules.taint_interfile_provider_tuple_array_container    targets/taint_interfile_provider_tuple_array_container/tuple_value/app.js    9
```

Latest broad Docker direct scan matrix after `9c24e76bb`:

```text
taint_interfile_provider_tuple_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_map_service_container count=4 expected=4 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_provider_shorthand_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_nested_array_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript', 'JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=['C++', 'C', 'Lisp', 'Scheme', 'Solidity', 'Lua', 'Ruby', 'Dart', 'OCaml', 'Scala', 'Cairo', 'Rust', 'C#', 'Hack', 'Circom', 'Clojure', 'TypeScript', 'PHP', 'Move on Aptos', 'Apex', 'Bash', 'Swift', 'Vue', 'R', 'Kotlin', 'Julia', 'Move on Sui', 'Vb'] status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=['XML', 'Python 3', 'JSON', 'HTML', 'Terraform', 'QL', 'YAML', 'Dockerfile', 'Prometheus Query Language', 'Python 2', 'Vue', 'Jsonnet', 'Protocol Buffers'] status=0
matrix_failures=0
```

Latest provider-spec-registration red proof before `9bfe35ed3`:

```text
provider_spec_registration_red count=0 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
```

Latest provider-spec-registration green proof after `9bfe35ed3`:

```text
provider_spec_registration_green count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
rules.taint_interfile_provider_spec_registration_container    targets/taint_interfile_provider_spec_registration_container/register_class/app.js    9
rules.taint_interfile_provider_spec_registration_container    targets/taint_interfile_provider_spec_registration_container/register_factory/app.js    9
rules.taint_interfile_provider_spec_registration_container    targets/taint_interfile_provider_spec_registration_container/register_value/app.js    9
```

Latest broad Docker direct scan matrix after `9bfe35ed3`:

```text
taint_interfile_provider_spec_registration_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_provider_tuple_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_map_service_container count=4 expected=4 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_provider_shorthand_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_nested_array_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript', 'JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=['C++', 'C', 'Lisp', 'Scheme', 'Solidity', 'Lua', 'Ruby', 'Dart', 'OCaml', 'Scala', 'Cairo', 'Rust', 'C#', 'Hack', 'Circom', 'Clojure', 'TypeScript', 'PHP', 'Move on Aptos', 'Apex', 'Bash', 'Swift', 'Vue', 'R', 'Kotlin', 'Julia', 'Move on Sui', 'Vb'] status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=['XML', 'Python 3', 'JSON', 'HTML', 'Terraform', 'QL', 'YAML', 'Dockerfile', 'Prometheus Query Language', 'Python 2', 'Vue', 'Jsonnet', 'Protocol Buffers'] status=0
matrix_failures=0
```

Latest TypeScript forward-ref-provider red proof before `4013b29f8`:

```text
forward_ref_provider_red count=0 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
```

Latest TypeScript forward-ref-provider green proof after `4013b29f8`:

```text
forward_ref_provider_green count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
rules.taint_interfile_typescript_forward_ref_provider_metadata    targets/taint_interfile_typescript_forward_ref_provider_metadata/inject_forward_ref/app.ts    20
rules.taint_interfile_typescript_forward_ref_provider_metadata    targets/taint_interfile_typescript_forward_ref_provider_metadata/provider_forward_ref/app.ts    20
rules.taint_interfile_typescript_forward_ref_provider_metadata    targets/taint_interfile_typescript_forward_ref_provider_metadata/token_forward_ref/app.ts    23
```

Latest broad Docker direct scan matrix after `4013b29f8`:

```text
taint_interfile_typescript_forward_ref_provider_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_provider_spec_registration_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_provider_tuple_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_map_service_container count=4 expected=4 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_provider_shorthand_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_nested_array_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript', 'JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=['C++', 'C', 'Lisp', 'Scheme', 'Solidity', 'Lua', 'Ruby', 'Dart', 'OCaml', 'Scala', 'Cairo', 'Rust', 'C#', 'Hack', 'Circom', 'Clojure', 'TypeScript', 'PHP', 'Move on Aptos', 'Apex', 'Bash', 'Swift', 'Vue', 'R', 'Kotlin', 'Julia', 'Move on Sui', 'Vb'] status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=['XML', 'Python 3', 'JSON', 'HTML', 'Terraform', 'QL', 'YAML', 'Dockerfile', 'Prometheus Query Language', 'Python 2', 'Vue', 'Jsonnet', 'Protocol Buffers'] status=0
matrix_failures=0
```

Latest named-provider-factory-deps red proof before `5ea01253b`:

```text
provider_named_factory_deps_red count=0 expected=3 errors=0 interfile_languages="TypeScript"
```

Latest named-provider-factory-deps green proof after `5ea01253b`:

```text
provider_named_factory_deps_green count=3 expected=3 errors=0 interfile_languages="TypeScript"
rules.taint_interfile_typescript_provider_named_factory_deps_metadata    targets/taint_interfile_typescript_provider_named_factory_deps_metadata/const_factory/app.ts    27
rules.taint_interfile_typescript_provider_named_factory_deps_metadata    targets/taint_interfile_typescript_provider_named_factory_deps_metadata/function_factory/app.ts    29
rules.taint_interfile_typescript_provider_named_factory_deps_metadata    targets/taint_interfile_typescript_provider_named_factory_deps_metadata/token_factory/app.ts    30
```

Latest broad Docker direct scan matrix after `5ea01253b`:

```text
taint_interfile_typescript_provider_named_factory_deps_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_factory_deps_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_js_constructor_parameter_to_self_provider_container count=2 expected=2 errors=0 interfile_languages="JavaScript"
taint_interfile_typescript_forward_ref_provider_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_provider_spec_registration_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_provider_tuple_array_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_map_service_container count=4 expected=4 errors=0 interfile_languages="JavaScript"
taint_interfile_typescript_provider_shorthand_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_nested_array_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_languages="TypeScript","JavaScript"
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_languages="TypeScript"
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_languages="C++","C","Lisp","Scheme","Solidity","Lua","Ruby","Dart","OCaml","Scala","Cairo","Rust","C#","Hack","Circom","Clojure","TypeScript","PHP","Move on Aptos","Apex","Bash","Swift","Vue","R","Kotlin","Julia","Move on Sui","Vb"
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_languages="XML","Python 3","JSON","HTML","Terraform","QL","YAML","Dockerfile","Prometheus Query Language","Python 2","Vue","Jsonnet","Protocol Buffers"
matrix_failures=0
```

Latest provider-factory-deps red proof before `3337b2b81`:

```text
provider_factory_deps_corrected_red count=0 expected=3 errors=0 interfile_languages="TypeScript"
```

Latest provider-factory-deps green proof after `3337b2b81`:

```text
provider_factory_deps_green count=3 expected=3 errors=0 interfile_languages="TypeScript"
rules.taint_interfile_typescript_provider_factory_deps_metadata    targets/taint_interfile_typescript_provider_factory_deps_metadata/class_deps/app.ts    26
rules.taint_interfile_typescript_provider_factory_deps_metadata    targets/taint_interfile_typescript_provider_factory_deps_metadata/inject_deps/app.ts    25
rules.taint_interfile_typescript_provider_factory_deps_metadata    targets/taint_interfile_typescript_provider_factory_deps_metadata/string_deps/app.ts    25
```

Latest broad Docker direct scan matrix after `3337b2b81`:

```text
taint_interfile_typescript_provider_factory_deps_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_js_constructor_parameter_to_self_provider_container count=2 expected=2 errors=0 interfile_languages="JavaScript"
taint_interfile_typescript_forward_ref_provider_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_provider_spec_registration_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_provider_tuple_array_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_map_service_container count=4 expected=4 errors=0 interfile_languages="JavaScript"
taint_interfile_typescript_provider_shorthand_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_nested_array_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_languages="TypeScript","JavaScript"
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_languages="JavaScript"
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_languages="TypeScript"
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_languages="TypeScript"
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_languages="C++","C","Lisp","Scheme","Solidity","Lua","Ruby","Dart","OCaml","Scala","Cairo","Rust","C#","Hack","Circom","Clojure","TypeScript","PHP","Move on Aptos","Apex","Bash","Swift","Vue","R","Kotlin","Julia","Move on Sui","Vb"
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_languages="XML","Python 3","JSON","HTML","Terraform","QL","YAML","Dockerfile","Prometheus Query Language","Python 2","Vue","Jsonnet","Protocol Buffers"
matrix_failures=0
```

Latest toSelf-provider red proof before `8229205c4`:

```text
to_self_provider_red count=0 expected=2 errors=0 interfile_lang_count=['JavaScript'] status=0
```

Latest toSelf-provider green proof after `8229205c4`:

```text
to_self_provider_green count=2 expected=2 errors=0 interfile_lang_count=['JavaScript'] status=0
rules.taint_interfile_js_constructor_parameter_to_self_provider_container    targets/taint_interfile_js_constructor_parameter_to_self_provider_container/direct/app.js    9
rules.taint_interfile_js_constructor_parameter_to_self_provider_container    targets/taint_interfile_js_constructor_parameter_to_self_provider_container/lifecycle/app.js    9
```

Latest broad Docker direct scan matrix after `8229205c4`:

```text
taint_interfile_js_constructor_parameter_to_self_provider_container count=2 expected=2 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_forward_ref_provider_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_provider_spec_registration_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_provider_tuple_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_map_service_container count=4 expected=4 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_provider_shorthand_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_nested_array_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_spread_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_token_metadata count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_alias_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_provider_metadata_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_provider_object_array_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_provider_lifecycle_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_hierarchical_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_async_provider_container count=3 expected=3 errors=0 interfile_lang_count=['TypeScript', 'JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container count=1 expected=1 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_lang_count=['JavaScript'] status=0
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=['TypeScript'] status=0
taint_interfile_language_matrix count=28 expected=28 errors=0 interfile_lang_count=['C++', 'C', 'Lisp', 'Scheme', 'Solidity', 'Lua', 'Ruby', 'Dart', 'OCaml', 'Scala', 'Cairo', 'Rust', 'C#', 'Hack', 'Circom', 'Clojure', 'TypeScript', 'PHP', 'Move on Aptos', 'Apex', 'Bash', 'Swift', 'Vue', 'R', 'Kotlin', 'Julia', 'Move on Sui', 'Vb'] status=0
taint_interfile_parser_smoke count=13 expected=13 errors=0 interfile_lang_count=['XML', 'Python 3', 'JSON', 'HTML', 'Terraform', 'QL', 'YAML', 'Dockerfile', 'Prometheus Query Language', 'Python 2', 'Vue', 'Jsonnet', 'Protocol Buffers'] status=0
matrix_failures=0
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

Latest broad Docker direct scan matrix after `b4762cf89`:

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
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_map_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_provider_alias_container count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_service_destructuring count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_nested_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_mutated_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_spread_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_rest_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_nested_mutated_service_container count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_object_factory_property count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_inline_object_factory_property count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_object_factory_property_alias count=2 expected=2 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias count=2 expected=2 errors=0 interfile_lang_count=1
taint_interfile_js_constructor_parameter_branch_alias count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_typescript_parameter_property count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_typescript_decorated_property_injection count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_typescript_decorated_constructor_parameter_injection count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_typescript_decorated_constructor_parameter_direct_injection count=1 expected=1 errors=0 interfile_lang_count=1
taint_interfile_typescript_decorated_metadata_injection count=3 expected=3 errors=0 interfile_lang_count=1
taint_interfile_typescript_injectable_constructor_metadata count=2 expected=2 errors=0 interfile_lang_count=1
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

## Latest Session Update: TypeScript Registry Provider Metadata Green

TypeScript provider metadata now resolves TSyringe-style registry decorator arrays and lowercase constructor injection decorators.

- `src/tainting/Object_initialization.ml` recognizes lowercase `@inject(...)` as an explicit injection decorator.
- Decorator metadata can now consume direct provider arrays such as `@registry([{ token: "source", useClass: Source }])`.
- Direct decorator arrays intentionally disable shorthand class-provider handling so arbitrary non-provider decorators with class arrays are not treated as provider metadata.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_registry_metadata.yaml` and `targets/taint_interfile_typescript_registry_metadata/` cover `useClass`, `useFactory`, and `useValue` registry providers.
- Existing JavaScript two-argument provider registration coverage now also includes object provider specs passed as `register("source", { useClass/useFactory/useValue: ... })`.

Red proof before the fix:

```text
registry_metadata_red count=0 expected=3 errors=0 interfile_languages=["TypeScript"]
```

Current targeted scans:

```text
registry_metadata_green count=3 expected=3 errors=0 interfile_languages=["TypeScript"]
rules.taint_interfile_typescript_registry_metadata    targets/taint_interfile_typescript_registry_metadata/class_provider/app.ts    18
rules.taint_interfile_typescript_registry_metadata    targets/taint_interfile_typescript_registry_metadata/factory_provider/app.ts    18
rules.taint_interfile_typescript_registry_metadata    targets/taint_interfile_typescript_registry_metadata/value_provider/app.ts    18

provider_spec_registration_count=6 expected=6 errors=0
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_registry_metadata count=3`, `taint_interfile_provider_spec_registration_container count=6`, `taint_interfile_typescript_provider_forward_alias_metadata count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- Docker `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.
- Signed checkpoint pushed: `22182d551` - `fix: resolve typescript registry provider metadata`.

Next resume point: continue auditing additional library-specific provider APIs, multi-provider collection injection forms, and tuple-like TypeScript metadata forms that appear in real frameworks.

## Latest Session Update: TypeScript Forward Provider Aliases Green

TypeScript provider metadata now resolves forward aliases that use `forwardRef` in `useExisting` provider objects.

- `src/tainting/Object_initialization.ml` reuses the same provider-key extraction for `useExisting`, `toService`, and `aliasTo` that already handles static strings, class tokens, and `forwardRef(() => Token)` provider keys.
- Provider metadata arrays are recorded once per entry so aliases can be revisited after later provider entries establish the target token binding.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_provider_forward_alias_metadata.yaml` and `targets/taint_interfile_typescript_provider_forward_alias_metadata/` lock direct class-token aliases, alias-before-target ordering, and imported provider arrays.

Red proof before the fix:

```text
provider_forward_alias_red count=0 expected=3 errors=0 interfile_languages="TypeScript"
```

Current targeted scan:

```text
provider_forward_alias_green count=3 expected=3 errors=0 interfile_languages="TypeScript"
rules.taint_interfile_typescript_provider_forward_alias_metadata    targets/taint_interfile_typescript_provider_forward_alias_metadata/class_token_alias/app.ts    29
rules.taint_interfile_typescript_provider_forward_alias_metadata    targets/taint_interfile_typescript_provider_forward_alias_metadata/direct_alias/app.ts    29
rules.taint_interfile_typescript_provider_forward_alias_metadata    targets/taint_interfile_typescript_provider_forward_alias_metadata/imported_alias/app.ts    11
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_provider_forward_alias_metadata count=3`, `taint_interfile_typescript_provider_environment_metadata count=3`, `taint_interfile_typescript_optional_metadata_injection count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- Docker `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.
- Signed checkpoint pushed: `41227c142` - `fix: resolve typescript forward provider aliases`.

Next resume point: continue auditing additional library-specific provider APIs and tuple-like TypeScript metadata forms that appear in real frameworks.

## Latest Session Update: TypeScript Environment Providers Green

TypeScript provider metadata now unwraps Angular-style environment provider wrappers.

- `src/tainting/Object_initialization.ml` records and consumes provider arrays through `makeEnvironmentProviders(...)` wrapper calls, including direct wrappers, named wrapper constants, imported wrapper constants, and spread wrapper expressions.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_provider_environment_metadata.yaml` and `targets/taint_interfile_typescript_provider_environment_metadata/` lock direct, named, and imported environment-provider metadata forms.
- Red Docker proof before the fix produced no findings for the wrapped provider arrays.

Red proof before the fix:

```text
provider_environment_red count=0 expected=3 errors=0 interfile_languages="TypeScript"
```

Current targeted scan:

```text
provider_environment_green count=3 expected=3 errors=0 interfile_languages="TypeScript"
rules.taint_interfile_typescript_provider_environment_metadata    targets/taint_interfile_typescript_provider_environment_metadata/direct_environment/app.ts    15
rules.taint_interfile_typescript_provider_environment_metadata    targets/taint_interfile_typescript_provider_environment_metadata/imported_environment/app.ts    11
rules.taint_interfile_typescript_provider_environment_metadata    targets/taint_interfile_typescript_provider_environment_metadata/named_environment/app.ts    19
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_provider_environment_metadata count=3`, `taint_interfile_typescript_optional_metadata_injection count=3`, `taint_interfile_typescript_provider_named_factory_deps_metadata count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- Docker `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.
- Signed checkpoint pushed: `caabeef2b` - `fix: resolve typescript environment providers`.

Next resume point: continue auditing additional library-specific provider APIs and tuple-like TypeScript metadata forms that appear in real frameworks.

## Latest Session Update: TypeScript Optional Metadata Injection Green

TypeScript DI metadata-only decorators now trigger typed constructor metadata when a decorated parameter is assigned to a field.

- `src/tainting/Object_initialization.ml` now distinguishes key-bearing injection decorators (`@Inject`, `@Autowired`) from metadata-only DI decorators (`@Optional`, `@Self`, `@SkipSelf`, `@Host`), so metadata-only decorators resolve typed parameters without becoming provider keys.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_optional_metadata_injection.yaml` and `targets/taint_interfile_typescript_optional_metadata_injection/` lock direct optional, field assignment, and multi-decorator location metadata forms.
- Red Docker proof before the fix found only the direct constructor cases and missed the field assignment case.

Red proof before the fix:

```text
optional_metadata_red count=2 expected=3 errors=0 interfile_languages="TypeScript"
rules.taint_interfile_typescript_optional_metadata_injection    targets/taint_interfile_typescript_optional_metadata_injection/multi_location/app.ts    13
rules.taint_interfile_typescript_optional_metadata_injection    targets/taint_interfile_typescript_optional_metadata_injection/optional_direct/app.ts    9
```

Current targeted scan:

```text
optional_metadata_green count=3 expected=3 errors=0 interfile_languages="TypeScript"
rules.taint_interfile_typescript_optional_metadata_injection    targets/taint_interfile_typescript_optional_metadata_injection/multi_location/app.ts    13
rules.taint_interfile_typescript_optional_metadata_injection    targets/taint_interfile_typescript_optional_metadata_injection/optional_direct/app.ts    9
rules.taint_interfile_typescript_optional_metadata_injection    targets/taint_interfile_typescript_optional_metadata_injection/self_field/app.ts    15
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_optional_metadata_injection count=3`, `taint_interfile_typescript_provider_named_factory_deps_metadata count=3`, `taint_interfile_typescript_provider_factory_deps_metadata count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- Docker `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.
- Signed checkpoint pushed: `38c821cc7` - `fix: resolve typescript optional metadata injection`.

Next resume point: continue auditing additional library-specific provider APIs and tuple-like TypeScript metadata forms that appear in real frameworks.

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
- Focused direct scans passed for TypeScript optional/location metadata decorators where `@Optional()`, `@Self()`, `@SkipSelf()`, or `@Host()` mark typed constructor parameters without an explicit provider key.
- Focused direct scans passed for TypeScript environment-provider metadata where `makeEnvironmentProviders(...)` wraps direct, named, or imported provider arrays.
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
- Focused direct scans passed for JavaScript service-container factory returns where `const services = createServices(); new App(services.source)` supplies the helper object from either a directly returned record or a returned local service object alias.
- Focused direct scans passed for JavaScript service-container factory aliases where an aliased `createServices()` call, an object-property factory call, or an object-property factory alias returns the service object used by `new App(services.source)`.
- Focused direct scans passed for JavaScript destructured service-container properties where `const { source } = services; new App(source)` supplies the helper object.
- Focused direct scans passed for JavaScript nested service-container property paths where `const services = { inputs: { source: new Source() } }; new App(services.inputs.source)` supplies the helper object.
- Focused direct scans passed for JavaScript mutated service-container properties where `const services = {}; services.source = new Source(); new App(services.source)` supplies the helper object.
- Focused direct scans passed for JavaScript spread service-container properties where `const services = { ...base }; new App(services.source)` supplies the helper object.
- Focused direct scans passed for JavaScript rest service-container properties where `const { logger, ...runtimeServices } = services; new App(runtimeServices.source)` supplies the helper object.
- Focused direct scans passed for JavaScript nested mutated service-container aliases where `const nested = services.nested; nested.source = new Source(); new App(services.nested.source)` supplies the helper object.
- Focused direct scans passed for JavaScript object factory properties where `const factories = { source: createSource }; const services = { source: factories.source() }; new App(services.source)` supplies the helper object.
- Focused direct scans passed for JavaScript inline object factory properties where `const factories = { source: () => new Source() }; const services = { source: factories.source() }; new App(services.source)` supplies the helper object.
- Focused direct scans passed for JavaScript object factory property aliases where `const sourceFactory = factories.source; const services = { source: sourceFactory() }; new App(services.source)` supplies the helper object for both named and inline factory properties.
- Focused direct scans passed for JavaScript mutated object factory property aliases where `registry.source = factories.source; const services = { source: registry.source() }; new App(services.source)` supplies the helper object for both named and inline factory properties.
- Focused direct scans passed for same-class conditional JavaScript constructor-parameter helper aliases where `const selected = condition() ? primary : fallback; new App(selected)` supplies the helper object.
- Direct probes passed for Java/Python/JavaScript override dispatch and multi-level inheritance.
- Broad direct scans passed for `taint_interfile_language_matrix` with 28 findings and `taint_interfile_parser_smoke` with 13 findings.
- `--dataflow-traces` on `taint_interfile_js` produced cross-file source, intermediate variable, and sink trace locations.
- `--dataflow-traces` on the Vue language-matrix fixture produced cross-file source, intermediate variable, and sink trace locations.
- Direct probes showed basic Java, JavaScript, TypeScript, and Python instance dispatch works.
- Direct probes showed field-backed object flows through constructors/methods work for Java, JavaScript, and Python.

Known boundaries:
- `generic` and `regex` are extended non-AST analyzers, not parser-backed target languages. Taint mode now rejects them with a structured `SemgrepError` and CLI help documents that they do not support taint mode.
- Untyped JavaScript constructor-parameter injection for direct constructor calls such as `constructor(source) { this.source = source }` with `new App(new Source())` is now covered. Local helper aliases, simple reassignments, simple factory-returned constructor helpers, factory-local helper aliases, arrow-function factories, simple higher-order factories, callable factory variable aliases, service-container object properties, service-container factory returns, service-container factory aliases, destructured service-container properties, nested service-container property paths, mutated service-container property assignments, spread service-container properties, rest service-container properties, nested mutated service-container aliases, object factory properties, inline object factory properties, object factory property aliases, mutated object factory property aliases, and same-class conditional branch aliases are covered. TypeScript keyless decorator metadata, DI-class constructor type metadata, optional/location constructor metadata, static provider metadata, provider aliases, async providers, hierarchical providers, lifecycle providers, provider-object arrays, provider tuples/specs, environment-provider wrappers, forward refs, toSelf bindings, and factory dependency metadata are covered when class type annotations or modeled provider metadata are statically visible. Broader dependency-injection object-shape variants remain unaudited, including runtime/reflection-only metadata without statically visible class types, additional library-specific provider APIs outside the modeled shapes, and deeper dynamic factory/container composition.
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

Object factory-property alias red proof before the property-factory alias mapping fix:

```text
taint_interfile_js_constructor_parameter_object_factory_property_alias count=0 expected=2 errors=0 interfile_lang_count=1
```

Object factory-property alias green proof after the property-factory alias mapping fix:

```text
taint_interfile_js_constructor_parameter_object_factory_property_alias count=2 expected=2 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_object_factory_property_alias    targets/taint_interfile_js_constructor_parameter_object_factory_property_alias/inline/app.js    9
rules.taint_interfile_js_constructor_parameter_object_factory_property_alias    targets/taint_interfile_js_constructor_parameter_object_factory_property_alias/named/app.js    9
```

Mutated object factory-property alias red proof before the property-assignment factory mapping fix:

```text
taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias count=0 expected=2 errors=0 interfile_lang_count=1
```

Mutated object factory-property alias green proof after the property-assignment factory mapping fix:

```text
taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias count=2 expected=2 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias    targets/taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias/inline/app.js    9
rules.taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias    targets/taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias/named/app.js    9
```

Service-container factory red proof before returned-record object-shape propagation:

```text
taint_interfile_js_constructor_parameter_service_container_factory count=0 expected=2 errors=0 interfile_lang_count=1
```

Service-container factory green proof after returned-record object-shape propagation:

```text
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_service_container_factory    targets/taint_interfile_js_constructor_parameter_service_container_factory/direct/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory    targets/taint_interfile_js_constructor_parameter_service_container_factory/local_alias/app.js    9
```

Service-container factory alias red proof before returned-object shape alias lookup:

```text
taint_interfile_js_constructor_parameter_service_container_factory_alias count=0 expected=3 errors=0 interfile_lang_count=1
```

Service-container factory alias green proof after returned-object shape alias lookup:

```text
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_service_container_factory_alias    targets/taint_interfile_js_constructor_parameter_service_container_factory_alias/local_alias/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory_alias    targets/taint_interfile_js_constructor_parameter_service_container_factory_alias/object_property/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory_alias    targets/taint_interfile_js_constructor_parameter_service_container_factory_alias/object_property_alias/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes, including `taint_interfile_js_constructor_parameter_instance count=1`, `taint_interfile_js_constructor_parameter_alias count=1`, `taint_interfile_js_constructor_parameter_reassigned_alias count=1`, `taint_interfile_js_constructor_parameter_factory count=1`, `taint_interfile_js_constructor_parameter_factory_local_alias count=1`, `taint_interfile_js_constructor_parameter_arrow_factory count=1`, `taint_interfile_js_constructor_parameter_higher_order_factory count=1`, `taint_interfile_js_constructor_parameter_factory_function_alias count=1`, `taint_interfile_js_constructor_parameter_service_container count=1`, `taint_interfile_js_constructor_parameter_string_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_service_container_factory count=2`, `taint_interfile_js_constructor_parameter_service_container_factory_alias count=3`, `taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3`, `taint_interfile_js_constructor_parameter_service_container_factory_composition count=3`, `taint_interfile_js_constructor_parameter_service_destructuring count=1`, `taint_interfile_js_constructor_parameter_nested_service_container count=1`, `taint_interfile_js_constructor_parameter_mutated_service_container count=1`, `taint_interfile_js_constructor_parameter_spread_service_container count=1`, `taint_interfile_js_constructor_parameter_rest_service_container count=1`, `taint_interfile_js_constructor_parameter_nested_mutated_service_container count=1`, `taint_interfile_js_constructor_parameter_object_factory_property count=1`, `taint_interfile_js_constructor_parameter_inline_object_factory_property count=1`, `taint_interfile_js_constructor_parameter_object_factory_property_alias count=2`, `taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias count=2`, `taint_interfile_js_constructor_parameter_branch_alias count=1`, `taint_interfile_constructor_field_instance count=2`, `taint_interfile_class_field_instance count=2`, `taint_interfile_callback_body_language_matrix count=6`, `taint_interfile_language_matrix count=28`, `taint_interfile_parser_smoke count=13`, and `matrix_failures=0`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: direct constructor-argument object shapes, simple local helper aliases, simple alias reassignments, simple factory-returned constructor helpers, factory-local helper aliases, variable-assigned arrow factories, simple higher-order factories, callable factory variable aliases, service-container object properties, static string-keyed, constant-keyed, simple computed-keyed, simple map-like, simple template-keyed, same-variable dynamic-keyed, same-expression dynamic-template-keyed, simple chained-map, explicit container API, provider-binding, provider API alias, provider method alias, provider alias, registration-map service-container object properties, TypeScript decorated property injection, TypeScript decorated constructor-parameter field injection, and TypeScript decorated constructor-parameter direct injection through static provider bindings, service-container factory returns, service-container factory aliases, direct destructuring from service-container factory returns, simple composed service-container factory returns, destructured service-container properties, nested service-container property paths, mutated service-container property assignments, object-spread service containers, object-rest service containers, nested mutated service-container aliases, object factory properties, inline object factory properties, object factory property aliases, mutated object factory property aliases, and same-class conditional branch aliases are covered. Broader dependency-injection forms remain unaudited, including runtime/reflection-only metadata without a TypeScript type annotation, runtime-only key equivalence, hierarchical/scoped containers, async providers, and additional library-specific provider APIs outside the modeled shapes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially runtime/reflection-only DI metadata, scoped containers, async providers, and additional library-specific provider APIs outside the modeled shapes.

---


## Latest Session Update: JavaScript Provider Alias Containers Green

JavaScript provider alias containers now preserve service-container object mappings when a provider key aliases another provider key that already has a class/value/factory binding.

- `src/tainting/Object_initialization.ml` now treats `useExisting`, `toService`, and `aliasTo` as provider methods.
- Alias provider methods resolve through `name_from_property_key_expr` and reuse `class_name_from_injected_provider_key`, with a class-reference fallback for class-token aliases.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_provider_alias_container.yaml` and `targets/taint_interfile_js_constructor_parameter_provider_alias_container/` lock `bind(...).toService(...)`, `provide(...).useExisting(...)`, and `register(...).aliasTo(...)` forms.

Red proof before provider alias resolution:

```text
provider_alias_red count=0 expected=3 errors=0 interfile=JavaScript
```

Green proof after provider alias resolution:

```text
provider_alias_green count=3 expected=3 errors=0 interfile=JavaScript
rules.taint_interfile_js_constructor_parameter_provider_alias_container    targets/taint_interfile_js_constructor_parameter_provider_alias_container/bind_to_service/app.js    9
rules.taint_interfile_js_constructor_parameter_provider_alias_container    targets/taint_interfile_js_constructor_parameter_provider_alias_container/provide_use_existing/app.js    9
rules.taint_interfile_js_constructor_parameter_provider_alias_container    targets/taint_interfile_js_constructor_parameter_provider_alias_container/register_alias_to/app.js    9
```

Current verification after the fix:

- Docker `make core` passes from the current working tree.
- Focused scans pass for provider alias containers and the neighboring provider/container fixtures.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_provider_alias_container count=3`, `taint_interfile_js_constructor_parameter_provider_method_alias_container count=3`, `taint_interfile_js_constructor_parameter_registration_map_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.
- Commit `b4762cf89` is signed and pushed.

Boundary note: provider aliases are covered when the aliased key can be resolved from static string, constant, computed, or modeled dynamic key expressions and the target key has already been bound. Forward aliases, async providers, scoped containers, and container-specific lifecycle APIs remain unaudited.

Next resume point: continue auditing DI forms that require container-specific lifecycle, scope, async, or forward-reference semantics beyond the static provider/key shapes now modeled.

---

## Latest Session Update: TypeScript Injectable Constructor Metadata Green

TypeScript DI-class constructor metadata now preserves object mappings when a class decorator such as `@Injectable()` marks a class as framework-managed and its constructor parameters have class type annotations but no explicit `@Inject()` provider key.

- `src/tainting/Object_initialization.ml` now recognizes DI class decorators such as `Injectable`, `Component`, `Controller`, `Service`, `Directive`, and `Resolver`.
- Constructor parameter class metadata is used only when the containing class has one of those DI decorators and the parameter does not already have a static provider key.
- Typed constructor parameters get direct object mappings, and assignments such as `this.source = source` record field mappings for later method calls.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_injectable_constructor_metadata.yaml` and `targets/taint_interfile_typescript_injectable_constructor_metadata/` lock both direct constructor-parameter and constructor-parameter-to-field flows.

Red proof before DI-class constructor metadata mapping:

```text
injectable_constructor_metadata count=0 expected=2 errors=0 interfile=TypeScript
```

Green proof after DI-class constructor metadata mapping:

```text
injectable_metadata_green count=2 expected=2 errors=0 interfile=TypeScript
rules.taint_interfile_typescript_injectable_constructor_metadata    targets/taint_interfile_typescript_injectable_constructor_metadata/direct/app.ts    10
rules.taint_interfile_typescript_injectable_constructor_metadata    targets/taint_interfile_typescript_injectable_constructor_metadata/field/app.ts    16
```

Current verification after the fix:

- Docker `make core` passes from the current working tree.
- Focused scans pass for the new injectable constructor metadata fixture, the keyless decorator metadata fixture, constructor parameter properties, and the existing explicit-key decorator injection fixtures.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_injectable_constructor_metadata count=2`, `taint_interfile_typescript_decorated_metadata_injection count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.
- Commit `8dd119409` is signed and pushed.

Boundary note: DI-class constructor metadata is covered when a recognized class decorator and a statically visible class type annotation are present. Metadata without statically visible class types, hierarchical/scoped containers, async providers, and additional framework-specific provider APIs remain unaudited.

Next resume point: continue auditing DI forms that require container-specific semantics beyond static provider keys and TypeScript class type metadata.

---

## Latest Session Update: TypeScript Decorated Metadata Injection Green

TypeScript keyless decorator metadata now preserves object mappings when `@Inject()` does not name a provider key and the decorated field or constructor parameter has a class type annotation.

- `src/tainting/Object_initialization.ml` now distinguishes injection decorators from provider-key decorators, reuses the existing static-key path when a key is present, and falls back to `vtype`/`ptype` class metadata only for keyless `@Inject()`/`@Autowired` shapes.
- Decorated constructor parameters now get object mappings for direct parameter use and, when assigned to `this.<field>`, field mappings for later method calls.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_decorated_metadata_injection.yaml` and `targets/taint_interfile_typescript_decorated_metadata_injection/` lock decorated property, direct constructor-parameter, and constructor-parameter-to-field flows.
- The fixture classes are intentionally unique per subcase to avoid unrelated interfile call-graph collisions from repeated `App`/`Source` names.

Red proof before the metadata fallback:

```text
metadata_red count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after keyless decorator metadata mapping:

```text
metadata count=3 expected=3 errors=0 interfile=TypeScript
rules.taint_interfile_typescript_decorated_metadata_injection    targets/taint_interfile_typescript_decorated_metadata_injection/constructor_direct/app.ts    14
rules.taint_interfile_typescript_decorated_metadata_injection    targets/taint_interfile_typescript_decorated_metadata_injection/constructor_field/app.ts    20
rules.taint_interfile_typescript_decorated_metadata_injection    targets/taint_interfile_typescript_decorated_metadata_injection/property/app.ts    17
```

Current verification after the fix:

- Docker `make core` passes from the current working tree.
- Focused scans pass for TypeScript decorated metadata injection and the three existing explicit-key decorator injection fixtures.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_decorated_metadata_injection count=3`, the explicit-key decorator fixtures, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.
- Commit `14c75e4c5` is signed and pushed.

Boundary note: keyless TypeScript decorator metadata is covered when class metadata is available as a field or parameter type annotation. DI-class constructor type metadata is covered in `8dd119409`. Metadata without statically visible class types, hierarchical/scoped containers, async providers, and framework-specific provider APIs remain unaudited.

Next resume point: continue auditing broader dependency-injection forms that are not covered by static provider keys or TypeScript decorator type metadata.

---

## Latest Session Update: JavaScript Registration-Map Containers Green

JavaScript registration-map containers now preserve service-container object mappings when a one-argument `register({ ... })` call stores provider specs inside an object map and consumers read through `resolve("source")`.

- `src/tainting/Object_initialization.ml` now records object-property class mappings for `register({ field: providerSpec })` calls when the provider spec resolves through `asClass`, `asValue`, or `asFunction`.
- The provider-spec resolver reuses the same class/value/factory semantics as chained provider APIs.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_registration_map_container.yaml` and `targets/taint_interfile_js_constructor_parameter_registration_map_container/` lock class-reference, constructed-value, and factory-lambda registration maps.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_registration_map_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after registration-map provider spec mapping:

```text
taint_interfile_js_constructor_parameter_registration_map_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_registration_map_container    targets/taint_interfile_js_constructor_parameter_registration_map_container/register_as_class/app.js    9
rules.taint_interfile_js_constructor_parameter_registration_map_container    targets/taint_interfile_js_constructor_parameter_registration_map_container/register_as_function/app.js    9
rules.taint_interfile_js_constructor_parameter_registration_map_container    targets/taint_interfile_js_constructor_parameter_registration_map_container/register_as_value/app.js    9
```

Current verification after the fix:

- Docker `make core` passes from the current working tree.
- Focused scans pass for registration-map containers, provider method aliases, existing provider chains, and existing provider API aliases.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_registration_map_container count=3`, `taint_interfile_js_constructor_parameter_provider_method_alias_container count=3`, `taint_interfile_js_constructor_parameter_provider_container count=3`, `taint_interfile_js_constructor_parameter_provider_api_alias_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: simple `register({ ... })` provider maps are covered for static field keys and class/value/factory provider specs. Framework injection metadata and more library-specific registration APIs remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially runtime/reflection-only DI metadata, scoped containers, async providers, and additional library-specific provider APIs outside the modeled shapes.

---

## Latest Session Update: JavaScript Provider Method Aliases Green

JavaScript provider method aliases now preserve service-container object mappings when provider chains use `asClass`, `asValue`, or `asFunction` after a `bind(...)` call.

- `src/tainting/Object_initialization.ml` now treats `asClass` like `to`/`useClass`, `asValue` like `toConstantValue`/`useValue`, and `asFunction` like `toDynamicValue`/`useFactory`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_provider_method_alias_container.yaml` and `targets/taint_interfile_js_constructor_parameter_provider_method_alias_container/` lock class-reference, constructed-value, and factory-lambda forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_provider_method_alias_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after provider method alias classification:

```text
taint_interfile_js_constructor_parameter_provider_method_alias_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_provider_method_alias_container    targets/taint_interfile_js_constructor_parameter_provider_method_alias_container/bind_as_class/app.js    9
rules.taint_interfile_js_constructor_parameter_provider_method_alias_container    targets/taint_interfile_js_constructor_parameter_provider_method_alias_container/bind_as_function/app.js    9
rules.taint_interfile_js_constructor_parameter_provider_method_alias_container    targets/taint_interfile_js_constructor_parameter_provider_method_alias_container/bind_as_value/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Focused provider scans pass for provider method aliases, existing provider chains, and existing provider API aliases.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_provider_method_alias_container count=3`, `taint_interfile_js_constructor_parameter_provider_container count=3`, `taint_interfile_js_constructor_parameter_provider_api_alias_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: chained provider method aliases are covered for class references, constructed values, and factory lambdas. Object-map registration APIs such as `register({ source: asClass(Source) })` remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially runtime/reflection-only DI metadata, scoped containers, async providers, and additional library-specific provider APIs.

---

## Latest Session Update: JavaScript Dynamic Template Service-Container Keys Green

JavaScript service-container object mappings now preserve structurally equivalent dynamic key expressions when static string evaluation fails. This covers non-static template keys such as `` `sou${sourceSuffix}` `` used on both provider and consumer sides.

- `src/tainting/Object_initialization.ml` now fingerprints dynamic property-key expressions from literal and variable components after the static string resolver fails.
- Dynamic key fingerprints include variable names and resolved SIds when available, and remain distinct from real string-literal keys.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container/` lock bracket assignment, `Map`-style `set`/`get`, and provider `bind(...).to(...)` plus `get(...)` for matching dynamic template expressions.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after structural dynamic key fingerprints:

```text
taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container    targets/taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container/assignment/app.js    9
rules.taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container    targets/taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container/map/app.js    9
rules.taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container    targets/taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container/provider/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Focused scans pass for dynamic-template-keyed, dynamic-variable-keyed, and existing static template-keyed service containers.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_dynamic_template_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_template_keyed_service_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: structurally matching dynamic keys are covered for supported literal/variable/concat/template expression forms. The engine still does not evaluate runtime function results or prove semantic equivalence for arbitrary expressions.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially runtime/reflection-only DI metadata, scoped containers, async providers, and additional library-specific provider APIs.

---

## Latest Session Update: JavaScript Dynamic Service-Container Keys Green

JavaScript service-container object mappings now preserve key identity when an unknown key variable is reused on both the provider write and consumer read sides. This covers dynamic keys without evaluating their runtime string value.

- `src/tainting/Object_initialization.ml` now falls back from static string-key extraction to a prefixed dynamic key identity for `G.N` key expressions.
- The dynamic key identity is distinct from real string literals, so a variable named `source` does not collide with a literal `"source"`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_dynamic_keyed_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_dynamic_keyed_service_container/` lock bracket assignment, `Map`-style `set`/`get`, and provider `bind(...).to(...)` plus `get(...)`.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after dynamic key identity fallback:

```text
taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_dynamic_keyed_service_container    targets/taint_interfile_js_constructor_parameter_dynamic_keyed_service_container/assignment/app.js    9
rules.taint_interfile_js_constructor_parameter_dynamic_keyed_service_container    targets/taint_interfile_js_constructor_parameter_dynamic_keyed_service_container/map/app.js    9
rules.taint_interfile_js_constructor_parameter_dynamic_keyed_service_container    targets/taint_interfile_js_constructor_parameter_dynamic_keyed_service_container/provider/app.js    9
```

Current verification after the fix:

- Docker `make core` passes from the current working tree.
- Focused dynamic-key direct scan passes with `taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1`.
- Adjacent focused scans pass for computed-keyed, template-keyed, provider, and explicit container API service containers.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_dynamic_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_template_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_provider_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: same-variable dynamic keys are covered for object bracket access, map-like `set`/`get`, and provider binding APIs. The engine still does not evaluate runtime key values and does not yet prove equivalence for separately written dynamic expressions such as two matching non-static template literals.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially dynamic template expressions, dynamic expression-key equivalence, and additional library-specific provider APIs.

---

## Latest Session Update: TypeScript Direct Decorated Constructor Injection Green

TypeScript decorated constructor-parameter direct injection now preserves object mappings when `constructor(@Inject("source") source) { sink(source.getInput()) }` consumes a statically bound provider key without assigning the parameter to a field.

- `src/tainting/Object_initialization.ml` now records an object mapping for the decorated constructor parameter itself when its static provider key has a known binding.
- The existing injected field mapping still covers field assignment forms, and focused scans were rerun for property, field-assignment constructor, and direct constructor parameter cases.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_decorated_constructor_parameter_direct_injection.yaml` and `targets/taint_interfile_typescript_decorated_constructor_parameter_direct_injection/` lock the direct constructor-parameter use form.

Red proof before the fix:

```text
taint_interfile_typescript_decorated_constructor_parameter_direct_injection count=0 expected=1 errors=0 interfile_lang_count=1
```

Green proof after injected parameter object mapping:

```text
taint_interfile_typescript_decorated_constructor_parameter_direct_injection count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_decorated_constructor_parameter_direct_injection    targets/taint_interfile_typescript_decorated_constructor_parameter_direct_injection/app.ts    17
```

Current verification after the fix:

- Docker `make core` passes.
- Focused scans pass for all current decorator forms: direct constructor parameter, field-assignment constructor parameter, and decorated property injection.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_decorated_constructor_parameter_direct_injection count=1`, `taint_interfile_typescript_decorated_constructor_parameter_injection count=1`, `taint_interfile_typescript_decorated_property_injection count=1`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: decorated constructor injection is covered when the decorator key is static and the provider key has a recorded binding. Runtime-dependent keys and runtime/reflection-only decorator metadata without type annotations remain unaudited. Keyless TypeScript type metadata is covered in `14c75e4c5`.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially dynamic template expressions, dynamic container keys, and additional library-specific provider APIs.

---

## Latest Session Update: TypeScript Decorated Constructor Injection Green

TypeScript decorated constructor-parameter injection now preserves object mappings when `constructor(@Inject("source") source) { this.source = source }` consumes a statically bound provider key.

- `src/tainting/Object_initialization.ml` now records injected field-to-provider-key mappings for both decorated fields and decorated constructor parameters.
- Injected fields are keyed by plain field names so constructor assignment IDs do not have to match later `this.<field>` read IDs.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_decorated_constructor_parameter_injection.yaml` and `targets/taint_interfile_typescript_decorated_constructor_parameter_injection/` lock the untyped decorated constructor-parameter assignment form.

Red proof before the fix:

```text
taint_interfile_typescript_decorated_constructor_parameter_injection count=0 expected=1 errors=0 interfile_lang_count=1
```

Green proof after injected constructor mapping:

```text
taint_interfile_typescript_decorated_constructor_parameter_injection count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_decorated_constructor_parameter_injection    targets/taint_interfile_typescript_decorated_constructor_parameter_injection/app.ts    21
```

Current verification after the fix:

- Docker `make core` passes.
- Focused scans pass for both decorator forms: `taint_interfile_typescript_decorated_constructor_parameter_injection count=1` and `taint_interfile_typescript_decorated_property_injection count=1`.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_decorated_constructor_parameter_injection count=1`, `taint_interfile_typescript_decorated_property_injection count=1`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: decorated constructor injection is covered when the decorated parameter is assigned to a class field and the static provider key has a recorded binding. Runtime-dependent keys and runtime/reflection-only decorator metadata without type annotations remain unaudited. Keyless TypeScript type metadata is covered in `14c75e4c5`.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially dynamic template expressions, dynamic container keys, and additional library-specific provider APIs.

---

## Latest Session Update: TypeScript Decorated Property Injection Green

TypeScript decorated property injection now preserves object mappings when an untyped `@Inject("source")` field consumes a statically bound provider key.

- `src/tainting/Object_initialization.ml` now recognizes `@Inject(...)` and `@Autowired(...)` field attributes.
- The injected key is resolved through existing static provider mappings such as `container.bind("source").to(Source)`.
- `cli/tests/default/e2e/rules/taint_interfile_typescript_decorated_property_injection.yaml` and `targets/taint_interfile_typescript_decorated_property_injection/` lock the untyped decorated property form.

Red proof before the fix:

```text
taint_interfile_typescript_decorated_property_injection count=0 expected=1 errors=0 interfile_lang_count=1
```

Green proof after injected property mapping:

```text
taint_interfile_typescript_decorated_property_injection count=1 expected=1 errors=0 interfile_lang_count=1
rules.taint_interfile_typescript_decorated_property_injection    targets/taint_interfile_typescript_decorated_property_injection/app.ts    20
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_typescript_decorated_property_injection count=1`, `taint_interfile_typescript_parameter_property count=1`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: decorated property injection is covered for static keys that match an already recorded provider binding. Runtime-dependent keys and runtime/reflection-only decorator metadata without type annotations remain unaudited. Constructor-parameter direct use is covered for static keys in `46daf9d1` and for keyless typed metadata in `14c75e4c5`.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially constructor-parameter decorators without field assignments, dynamic template expressions, dynamic container keys, and additional library-specific provider APIs.

---

## Latest Session Update: JavaScript Provider API Aliases Green

JavaScript provider-style service containers now preserve object-property mappings through `provide(key).useClass(Class)`, `provide(key).useValue(new Class())`, and `provide(key).useFactory(() => new Class())` chains.

- `src/tainting/Object_initialization.ml` now recognizes `provide` as a static keyed binding method.
- Provider methods `useClass`, `useValue`, and `useFactory` reuse the same provider value handling as `to`, `toConstantValue`, and `toDynamicValue`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_provider_api_alias_container.yaml` and `targets/taint_interfile_js_constructor_parameter_provider_api_alias_container/` lock class-provider, value-provider, and factory-provider alias forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_provider_api_alias_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after provider API alias recognition:

```text
taint_interfile_js_constructor_parameter_provider_api_alias_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_provider_api_alias_container    targets/taint_interfile_js_constructor_parameter_provider_api_alias_container/provide_use_class/app.js    9
rules.taint_interfile_js_constructor_parameter_provider_api_alias_container    targets/taint_interfile_js_constructor_parameter_provider_api_alias_container/provide_use_factory/app.js    9
rules.taint_interfile_js_constructor_parameter_provider_api_alias_container    targets/taint_interfile_js_constructor_parameter_provider_api_alias_container/provide_use_value/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_provider_api_alias_container count=3`, `taint_interfile_js_constructor_parameter_provider_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: provider API aliases are covered for static keys and provider values expressed as class references, constructed values, or factory lambda returns. Runtime-dependent keys, decorator/metadata-based framework injection, and unlisted provider APIs remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially decorator/metadata-based framework injection, dynamic template expressions, dynamic container keys, and additional library-specific provider APIs.

---

## Latest Session Update: JavaScript Provider Service Containers Green

JavaScript provider-style service containers now preserve object-property mappings through Inversify-style binding chains such as `container.bind("source").to(Source)` followed by `container.get("source")`.

- `src/tainting/Object_initialization.ml` now recognizes provider methods `to`, `toConstantValue`, and `toDynamicValue` after a static keyed `bind`/`register`/`set` call.
- Bare class references are treated as constructed providers only inside `.to(ClassName)`, not as general object instances.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_provider_container.yaml` and `targets/taint_interfile_js_constructor_parameter_provider_container/` lock class-provider, constant-value-provider, and dynamic-value-provider forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_provider_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after provider binding recognition:

```text
taint_interfile_js_constructor_parameter_provider_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_provider_container    targets/taint_interfile_js_constructor_parameter_provider_container/bind_to_class/app.js    9
rules.taint_interfile_js_constructor_parameter_provider_container    targets/taint_interfile_js_constructor_parameter_provider_container/bind_to_constant/app.js    9
rules.taint_interfile_js_constructor_parameter_provider_container    targets/taint_interfile_js_constructor_parameter_provider_container/bind_to_dynamic/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_provider_container count=3`, `taint_interfile_js_constructor_parameter_container_api_service_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: provider chains are covered for static keys and provider values expressed as class references, constructed constants, or dynamic lambda returns. Runtime-dependent keys, decorator/metadata-based framework injection, and unlisted provider APIs remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially decorator/metadata-based framework injection, dynamic template expressions, dynamic container keys, and additional library-specific provider APIs.

---

## Latest Session Update: JavaScript Container API Service Containers Green

JavaScript service containers now preserve object-property mappings through explicit non-Map container method pairs such as `register`/`resolve` and `bind`/`get`.

- `src/tainting/Object_initialization.ml` now recognizes `get`, `resolve`, and `lookup` as static keyed reads.
- The same path recognizes `set`, `register`, and `bind` as static keyed writes, including direct chained calls.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_container_api_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_container_api_service_container/` lock `register`/`resolve`, `bind`/`get`, and chained `register`/`resolve` forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_container_api_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after container method alias normalization:

```text
taint_interfile_js_constructor_parameter_container_api_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_container_api_service_container    targets/taint_interfile_js_constructor_parameter_container_api_service_container/bind_get/app.js    9
rules.taint_interfile_js_constructor_parameter_container_api_service_container    targets/taint_interfile_js_constructor_parameter_container_api_service_container/chained/app.js    9
rules.taint_interfile_js_constructor_parameter_container_api_service_container    targets/taint_interfile_js_constructor_parameter_container_api_service_container/register_resolve/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_container_api_service_container count=3`, `taint_interfile_js_constructor_parameter_chained_map_service_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: explicit non-Map method pairs are covered for static keys and known constructed values. Runtime-dependent keys, decorator/metadata-based framework injection, and unlisted library-specific APIs remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially decorator/metadata-based framework injection, dynamic template expressions, dynamic container keys, and additional library-specific provider APIs.

---

## Latest Session Update: JavaScript Chained Map Service Containers Green

JavaScript service containers now preserve object-property mappings through simple chained Map APIs such as `new Map().set("source", new Source()).get("source")`.

- `src/tainting/Object_initialization.ml` now collects static `.set(key, value)` entries from nested call chains.
- Chained entries are attached when a variable is initialized from a chain, when a factory returns a chain, and when a constructor argument reads directly from `.set(...).get(key)`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_chained_map_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_chained_map_service_container/` lock variable-initialized, direct constructor-argument, and factory-return chain forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_chained_map_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after chained-map entry collection:

```text
taint_interfile_js_constructor_parameter_chained_map_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_chained_map_service_container    targets/taint_interfile_js_constructor_parameter_chained_map_service_container/direct/app.js    9
rules.taint_interfile_js_constructor_parameter_chained_map_service_container    targets/taint_interfile_js_constructor_parameter_chained_map_service_container/factory/app.js    9
rules.taint_interfile_js_constructor_parameter_chained_map_service_container    targets/taint_interfile_js_constructor_parameter_chained_map_service_container/variable/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_chained_map_service_container count=3`, `taint_interfile_js_constructor_parameter_template_keyed_service_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: simple chained Map APIs are covered for static keys and known constructed/factory-returned values. Runtime-dependent keys, framework-specific injection decorators/metadata, and additional library-specific APIs remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection, dynamic template expressions, dynamic container keys, and additional library-specific container APIs.

---

## Latest Session Update: JavaScript Template-Keyed Service Containers Green

JavaScript service containers now preserve object-property mappings through static template literals such as ``services[`source`]`` and static interpolated keys such as ``services[`sou${SOURCE_SUFFIX}`]`` when the interpolated values are already-known string constants.

- `src/tainting/Object_initialization.ml` now evaluates `ConcatString(InterpolatedConcat)` expressions through the same static string collector used by literal, constant, and `+`-concatenated keys.
- Static template keys feed both bracket access and map-like `.set(...)` / `.get(...)` paths because they share `name_from_static_property_expr`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_template_keyed_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_template_keyed_service_container/` lock literal template, interpolated constant template, and map-template forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_template_keyed_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after template static-string evaluation:

```text
taint_interfile_js_constructor_parameter_template_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_template_keyed_service_container    targets/taint_interfile_js_constructor_parameter_template_keyed_service_container/expression/app.js    9
rules.taint_interfile_js_constructor_parameter_template_keyed_service_container    targets/taint_interfile_js_constructor_parameter_template_keyed_service_container/literal/app.js    9
rules.taint_interfile_js_constructor_parameter_template_keyed_service_container    targets/taint_interfile_js_constructor_parameter_template_keyed_service_container/map/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_template_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_map_service_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: static JavaScript template keys are covered when every template part resolves to a literal or previously recorded string constant. Runtime-dependent template values, dynamic keys, non-Map container APIs, and framework/container injection remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially non-Map container APIs, framework/container injection, dynamic template expressions, and dynamic map keys.

---

## Latest Session Update: JavaScript Map Service Containers Green

JavaScript service containers now preserve object-property mappings through simple map-like method APIs such as `services.set("source", new Source())` and `services.get("source")`.

- `src/tainting/Object_initialization.ml` now normalizes one-argument `.get(staticKey)` calls into the same object-property path form used by direct property and bracket reads.
- `.set(staticKey, value)` calls feed the existing object-property mapping path, so direct map writes, static string-constant keys, and service-map factory returns use the same class/factory alias bookkeeping as object-property assignments.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_map_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_map_service_container/` lock literal-key, constant-key, and factory-return map forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_map_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after map-like method normalization:

```text
taint_interfile_js_constructor_parameter_map_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_map_service_container    targets/taint_interfile_js_constructor_parameter_map_service_container/constant_key/app.js    9
rules.taint_interfile_js_constructor_parameter_map_service_container    targets/taint_interfile_js_constructor_parameter_map_service_container/factory/app.js    9
rules.taint_interfile_js_constructor_parameter_map_service_container    targets/taint_interfile_js_constructor_parameter_map_service_container/literal/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_map_service_container count=3`, `taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: simple map-like `.set(staticKey, value)` and `.get(staticKey)` service-container flows are covered for literal keys, direct string constants, static template keys, chained Map APIs, and returned service-map factories. Runtime-dependent keys, non-Map container APIs, and framework/container injection remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially non-Map container APIs, framework/container injection, and dynamic map keys.

---

## Latest Session Update: JavaScript Computed-Keyed Service Containers Green

JavaScript service containers now preserve object-property mappings through simple static string expressions used as bracket keys, such as `services["sou" + "rce"]` or `services[SOURCE_PREFIX + "rce"]`.

- `src/tainting/Object_initialization.ml` now evaluates static string expressions made from literal strings, previously recorded string constants, and `+` concatenation.
- The string-key prepass records those computed key values before returned-object and object-property analysis runs.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_computed_keyed_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_computed_keyed_service_container/` lock object-literal, later assignment, and factory-return forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after static string-expression evaluation:

```text
taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_computed_keyed_service_container    targets/taint_interfile_js_constructor_parameter_computed_keyed_service_container/assignment/app.js    9
rules.taint_interfile_js_constructor_parameter_computed_keyed_service_container    targets/taint_interfile_js_constructor_parameter_computed_keyed_service_container/factory/app.js    9
rules.taint_interfile_js_constructor_parameter_computed_keyed_service_container    targets/taint_interfile_js_constructor_parameter_computed_keyed_service_container/literal/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_computed_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: simple static string concatenation is covered for JavaScript bracket keys in direct object reads, property assignments, and object-shaped factory returns. Dynamic template expressions, dynamic map keys, non-Map container APIs, and framework/container injection remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially non-Map container APIs, framework/container injection, dynamic template expressions, and dynamic map keys.

---

## Latest Session Update: JavaScript Constant-Keyed Service Containers Green

JavaScript service containers now preserve object-property mappings through simple string constants used as bracket keys, such as `services[SOURCE_KEY]` where `SOURCE_KEY = "source"`.

- `src/tainting/Object_initialization.ml` now runs a string-constant prepass before returned-object and object-property analysis.
- Static property-key normalization resolves `G.N` key expressions through the string-constant map before falling back to unresolved dynamic-key behavior.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_constant_keyed_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_constant_keyed_service_container/` lock object-literal, later assignment, and factory-return forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after string-constant key normalization:

```text
taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_constant_keyed_service_container    targets/taint_interfile_js_constructor_parameter_constant_keyed_service_container/assignment/app.js    9
rules.taint_interfile_js_constructor_parameter_constant_keyed_service_container    targets/taint_interfile_js_constructor_parameter_constant_keyed_service_container/factory/app.js    9
rules.taint_interfile_js_constructor_parameter_constant_keyed_service_container    targets/taint_interfile_js_constructor_parameter_constant_keyed_service_container/literal/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_constant_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_string_keyed_service_container count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: direct string constants are covered for JavaScript bracket keys in direct object reads, property assignments, and object-shaped factory returns. Dynamic computed expressions, dynamic map keys, and non-Map container APIs remain unaudited.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially non-Map container APIs, framework/container injection, dynamic template expressions, and dynamic map keys.

---

## Latest Session Update: JavaScript String-Keyed Service Containers Green

JavaScript service containers now preserve object-property mappings through static string-keyed bracket access such as `services["source"]`.

- `src/tainting/Object_initialization.ml` now normalizes `ArrayAccess` with a static string literal key into the same object-property path form used by `DotAccess`.
- Computed object-literal keys with static string literals now feed object-property mappings in direct service objects and returned service-object factories.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_string_keyed_service_container.yaml` and `targets/taint_interfile_js_constructor_parameter_string_keyed_service_container/` lock object-literal, later assignment, and factory-return forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_string_keyed_service_container count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after static string-key normalization:

```text
taint_interfile_js_constructor_parameter_string_keyed_service_container count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_string_keyed_service_container    targets/taint_interfile_js_constructor_parameter_string_keyed_service_container/assignment/app.js    9
rules.taint_interfile_js_constructor_parameter_string_keyed_service_container    targets/taint_interfile_js_constructor_parameter_string_keyed_service_container/factory/app.js    9
rules.taint_interfile_js_constructor_parameter_string_keyed_service_container    targets/taint_interfile_js_constructor_parameter_string_keyed_service_container/literal/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_string_keyed_service_container count=3`, `taint_interfile_js_constructor_parameter_service_container_factory_composition count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: static string-keyed JavaScript object properties are covered for direct object reads, property assignments, and object-shaped factory returns. Dynamic keys remain intentionally unresolved unless a later slice adds constant propagation for key values.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially dynamic container lookups and framework/container injection.

---

## Latest Session Update: JavaScript Composed Service Container Factories Green

JavaScript service-container factory composition now preserves returned object-shape information when one factory returns another factory's service object.

- `src/tainting/Object_initialization.ml` now copies returned object-property entries from a callee factory call into the caller factory's returned object-shape mapping.
- Local variables inside a factory can carry object-property entries from a factory call to a later `return services`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_service_container_factory_composition.yaml` and `targets/taint_interfile_js_constructor_parameter_service_container_factory_composition/` lock direct return-call composition, local-return-alias composition, and destructuring from the composed factory.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_service_container_factory_composition count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after returned object-shape composition:

```text
taint_interfile_js_constructor_parameter_service_container_factory_composition count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_service_container_factory_composition    targets/taint_interfile_js_constructor_parameter_service_container_factory_composition/destructured/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory_composition    targets/taint_interfile_js_constructor_parameter_service_container_factory_composition/direct_return/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory_composition    targets/taint_interfile_js_constructor_parameter_service_container_factory_composition/local_alias/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_service_container_factory_composition count=3`, `taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: simple service-container factory composition is covered when the composed callee has already been seen in the file. Broader dependency-injection forms remain unaudited, including framework/container injection, late-defined factory composition, and deeper dynamic container lookups.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection, late-defined factory composition, and dynamic container lookups.

---

## Latest Session Update: JavaScript Service Container Factory Destructuring Green

JavaScript direct destructuring from service-container factory returns now preserves returned object-shape information before constructor-parameter helper resolution.

- `src/tainting/Object_initialization.ml` now lets destructuring read object-property entries from either a named service object or a call whose callee has recorded returned object-property mappings.
- The returned-object lookup reuses the existing factory alias resolution, so destructuring works for direct factory calls, simple function aliases, and object-property factory calls.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_service_container_factory_destructuring.yaml` and `targets/taint_interfile_js_constructor_parameter_service_container_factory_destructuring/` lock direct, function-alias, and object-property call forms.

Red proof before the fix:

```text
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=0 expected=3 errors=0 interfile_lang_count=1
```

Green proof after destructuring reads returned object shapes:

```text
taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_service_container_factory_destructuring    targets/taint_interfile_js_constructor_parameter_service_container_factory_destructuring/direct/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory_destructuring    targets/taint_interfile_js_constructor_parameter_service_container_factory_destructuring/function_alias/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory_destructuring    targets/taint_interfile_js_constructor_parameter_service_container_factory_destructuring/object_property/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including `taint_interfile_js_constructor_parameter_service_container_factory_destructuring count=3`, `taint_interfile_js_constructor_parameter_service_container_factory_alias count=3`, `taint_interfile_js_constructor_parameter_service_container_factory count=2`, `taint_interfile_language_matrix count=28`, and `taint_interfile_parser_smoke count=13`.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Boundary note: named service-object destructuring, direct service-container factory returns, factory aliases, and direct destructuring from returned service-container factories are covered. Broader dependency-injection forms remain unaudited, including framework/container injection and deeper factory composition.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and deeper factory composition.

---

## Latest Session Update: JavaScript Service Container Factory Aliases Green

JavaScript service-container factory aliases now preserve returned object-shape information when a service-object factory is called through a local alias, an object property, or an object-property alias.

- `src/tainting/Object_initialization.ml` now treats functions with returned object-property mappings as aliasable factory functions, not only functions with direct class-return mappings.
- Returned object-shape lookup follows simple function aliases and object-property factory references before copying service properties to variables initialized from those calls.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_service_container_factory_alias.yaml` and `targets/taint_interfile_js_constructor_parameter_service_container_factory_alias/` lock local alias, object-property call, and object-property alias forms.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_service_container_factory_alias count=3 expected=3 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_service_container_factory_alias    targets/taint_interfile_js_constructor_parameter_service_container_factory_alias/local_alias/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory_alias    targets/taint_interfile_js_constructor_parameter_service_container_factory_alias/object_property/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory_alias    targets/taint_interfile_js_constructor_parameter_service_container_factory_alias/object_property_alias/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new three-finding service-container factory alias fixture, the service-container factory fixture, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and deeper factory composition.

---

## Latest Session Update: JavaScript Service Container Factories Green

JavaScript service-container factory returns now preserve object-shape information when a helper function returns a service object that is later passed into a constructor through one of its properties.

- `src/tainting/Object_initialization.ml` records object-property mappings returned by functions, including both direct `return { source: new Source() }` records and local object aliases returned from the factory body.
- `record_object_property_mappings` copies those returned object shapes when a variable is initialized from a call such as `const services = createServices()`.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_service_container_factory.yaml` and `targets/taint_interfile_js_constructor_parameter_service_container_factory/` lock direct and local-alias factory returns.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_service_container_factory count=2 expected=2 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_service_container_factory    targets/taint_interfile_js_constructor_parameter_service_container_factory/direct/app.js    9
rules.taint_interfile_js_constructor_parameter_service_container_factory    targets/taint_interfile_js_constructor_parameter_service_container_factory/local_alias/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new two-finding service-container factory fixture, the object factory-property alias fixtures, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection, service-container factory aliases, and deeper factory composition.

---

## Latest Session Update: JavaScript Mutated Object Factory Property Aliases Green

JavaScript mutated object factory property aliases now preserve object-shape information when a factory is assigned into an object property before being called through that property.

- `src/tainting/Object_initialization.ml` records property assignments such as `registry.source = factories.source` as factory mappings, including named factory functions and inline factory-return mappings.
- The same assignment path mirrors mappings through existing object-property aliases, matching the behavior already used for constructed object property assignments.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias.yaml` and `targets/taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias/` lock both named and inline mutated factory-property alias forms.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias count=2 expected=2 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias    targets/taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias/inline/app.js    9
rules.taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias    targets/taint_interfile_js_constructor_parameter_mutated_object_factory_property_alias/named/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new two-finding mutated object factory-property alias fixture, the object factory-property alias fixture, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

Next resume point: continue auditing broader dependency-injection object-shape forms, especially framework/container injection and deeper factory composition.

---

## Latest Session Update: JavaScript Object Factory Property Aliases Green

JavaScript object factory property aliases now preserve object-shape information when a factory is read from an object property into a callable local before construction.

- `src/tainting/Object_initialization.ml` resolves `factories.source` to either a named factory function or a direct inline factory return mapping, so aliases such as `const sourceFactory = factories.source` can feed later `sourceFactory()` calls.
- `cli/tests/default/e2e/rules/taint_interfile_js_constructor_parameter_object_factory_property_alias.yaml` and `targets/taint_interfile_js_constructor_parameter_object_factory_property_alias/` lock both named and inline factory-property alias forms.
- Focused direct scan passed for `const sourceFactory = factories.source; const services = { source: sourceFactory() }; new App(services.source)`.

Current targeted scan:

```text
taint_interfile_js_constructor_parameter_object_factory_property_alias count=2 expected=2 errors=0 interfile_lang_count=1
rules.taint_interfile_js_constructor_parameter_object_factory_property_alias    targets/taint_interfile_js_constructor_parameter_object_factory_property_alias/inline/app.js    9
rules.taint_interfile_js_constructor_parameter_object_factory_property_alias    targets/taint_interfile_js_constructor_parameter_object_factory_property_alias/named/app.js    9
```

Current verification after the fix:

- Docker `make core` passes.
- Full direct regression matrix passes with `matrix_failures=0`, including the new two-finding object factory-property alias fixture, the 28-finding language matrix, and the 13-finding parser-smoke suite.
- `git diff --check` passes.
- `python3 -m py_compile cli/tests/default/e2e/test_taint_interfile.py` passes.

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
