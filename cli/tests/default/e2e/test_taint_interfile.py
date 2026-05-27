import json
import re
from pathlib import Path

import pytest

from semgrep.constants import OutputFormat
from tests.fixtures import RunSemgrep


INTERFILE_LANGUAGE_MATRIX = {
    "rules.taint_interfile_matrix_apex": (
        "Apex",
        "targets/taint_interfile_language_matrix/apex/App.cls",
        3,
    ),
    "rules.taint_interfile_matrix_bash": (
        "Bash",
        "targets/taint_interfile_language_matrix/bash/app.sh",
        1,
    ),
    "rules.taint_interfile_matrix_c": (
        "C",
        "targets/taint_interfile_language_matrix/c/app.c",
        4,
    ),
    "rules.taint_interfile_matrix_cairo": (
        "Cairo",
        "targets/taint_interfile_language_matrix/cairo/app.cairo",
        2,
    ),
    "rules.taint_interfile_matrix_circom": (
        "Circom",
        "targets/taint_interfile_language_matrix/circom/app.circom",
        2,
    ),
    "rules.taint_interfile_matrix_clojure": (
        "Clojure",
        "targets/taint_interfile_language_matrix/clojure/app.clj",
        1,
    ),
    "rules.taint_interfile_matrix_cpp": (
        "C++",
        "targets/taint_interfile_language_matrix/cpp/app.cpp",
        4,
    ),
    "rules.taint_interfile_matrix_csharp": (
        "C#",
        "targets/taint_interfile_language_matrix/csharp/App.cs",
        3,
    ),
    "rules.taint_interfile_matrix_dart": (
        "Dart",
        "targets/taint_interfile_language_matrix/dart/app.dart",
        2,
    ),
    "rules.taint_interfile_matrix_hack": (
        "Hack",
        "targets/taint_interfile_language_matrix/hack/app.php",
        2,
    ),
    "rules.taint_interfile_matrix_julia": (
        "Julia",
        "targets/taint_interfile_language_matrix/julia/app.jl",
        1,
    ),
    "rules.taint_interfile_matrix_kotlin": (
        "Kotlin",
        "targets/taint_interfile_language_matrix/kotlin/app.kt",
        2,
    ),
    "rules.taint_interfile_matrix_lua": (
        "Lua",
        "targets/taint_interfile_language_matrix/lua/app.lua",
        1,
    ),
    "rules.taint_interfile_matrix_lisp": (
        "Lisp",
        "targets/taint_interfile_language_matrix/lisp/app.lisp",
        1,
    ),
    "rules.taint_interfile_matrix_move_on_aptos": (
        "Move on Aptos",
        "targets/taint_interfile_language_matrix/move_on_aptos/app.move",
        3,
    ),
    "rules.taint_interfile_matrix_move_on_sui": (
        "Move on Sui",
        "targets/taint_interfile_language_matrix/move_on_sui/app.move",
        3,
    ),
    "rules.taint_interfile_matrix_ocaml": (
        "OCaml",
        "targets/taint_interfile_language_matrix/ocaml/app.ml",
        1,
    ),
    "rules.taint_interfile_matrix_php": (
        "PHP",
        "targets/taint_interfile_language_matrix/php/app.php",
        2,
    ),
    "rules.taint_interfile_matrix_r": (
        "R",
        "targets/taint_interfile_language_matrix/r/app.R",
        1,
    ),
    "rules.taint_interfile_matrix_ruby": (
        "Ruby",
        "targets/taint_interfile_language_matrix/ruby/app.rb",
        1,
    ),
    "rules.taint_interfile_matrix_rust": (
        "Rust",
        "targets/taint_interfile_language_matrix/rust/app.rs",
        2,
    ),
    "rules.taint_interfile_matrix_scala": (
        "Scala",
        "targets/taint_interfile_language_matrix/scala/App.scala",
        2,
    ),
    "rules.taint_interfile_matrix_scheme": (
        "Scheme",
        "targets/taint_interfile_language_matrix/scheme/app.scm",
        1,
    ),
    "rules.taint_interfile_matrix_solidity": (
        "Solidity",
        "targets/taint_interfile_language_matrix/solidity/App.sol",
        2,
    ),
    "rules.taint_interfile_matrix_swift": (
        "Swift",
        "targets/taint_interfile_language_matrix/swift/app.swift",
        2,
    ),
    "rules.taint_interfile_matrix_typescript": (
        "TypeScript",
        "targets/taint_interfile_language_matrix/typescript/app.ts",
        3,
    ),
    "rules.taint_interfile_matrix_vue": (
        "Vue",
        "targets/taint_interfile_language_matrix/vue/app.vue",
        5,
    ),
    "rules.taint_interfile_matrix_vb": (
        "Vb",
        "targets/taint_interfile_language_matrix/vb/App.vb",
        3,
    ),
}

INTERFILE_PARSER_SMOKE_LANGUAGES = {
    "Dockerfile",
    "HTML",
    "JSON",
    "Jsonnet",
    "Prometheus Query Language",
    "Protocol Buffers",
    "Python 2",
    "Python 3",
    "QL",
    "Terraform",
    "Vue",
    "XML",
    "YAML",
}

INTERFILE_PARSER_SMOKE_FINDINGS = {
    "rules.taint_interfile_smoke_dockerfile",
    "rules.taint_interfile_smoke_html",
    "rules.taint_interfile_smoke_json",
    "rules.taint_interfile_smoke_jsonnet",
    "rules.taint_interfile_smoke_promql",
    "rules.taint_interfile_smoke_protobuf",
    "rules.taint_interfile_smoke_python2",
    "rules.taint_interfile_smoke_python3",
    "rules.taint_interfile_smoke_ql",
    "rules.taint_interfile_smoke_terraform",
    "rules.taint_interfile_smoke_vue",
    "rules.taint_interfile_smoke_xml",
    "rules.taint_interfile_smoke_yaml",
}

LANGUAGE_ID_ALIASES = {
    "javascript": "js",
    "typescript": "ts",
}


def _normalize_ocaml_string_text(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"\\\s*", " ", text))


def _rule_languages(rule_text: str) -> set[str]:
    languages = set()
    in_languages = False
    for line in rule_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("languages: ["):
            in_languages = False
            languages.update(
                language.strip().strip("'\"")
                for language in stripped.removeprefix("languages: [")
                .removesuffix("]")
                .split(",")
                if language.strip()
            )
        elif stripped == "languages:":
            in_languages = True
        elif in_languages and stripped.startswith("- "):
            languages.add(stripped.removeprefix("- ").strip().strip("'\""))
        elif in_languages and re.match(r"^[a-zA-Z_-]+:", stripped):
            in_languages = False
    return languages


@pytest.mark.quick
def test_interfile_taint_rule_fixtures_cover_all_target_languages():
    e2e_root = Path(__file__).parent
    cli_root = Path(__file__).parents[3]
    lang_json = cli_root / "src" / "semgrep" / "semgrep_interfaces" / "lang.json"
    target_languages = {
        language["id"]
        for language in json.loads(lang_json.read_text())
        if language["is_target_language"]
    }

    rule_languages = set()
    for rule_path in (e2e_root / "rules").glob("taint_interfile_*.yaml"):
        rule_languages.update(_rule_languages(rule_path.read_text()))

    normalized_rule_languages = {
        LANGUAGE_ID_ALIASES.get(language, language) for language in rule_languages
    }
    assert target_languages - normalized_rule_languages == set()
    assert normalized_rule_languages - target_languages == set()


@pytest.mark.quick
def test_taint_scope_does_not_advertise_generic_regex_fallback():
    repo_root = Path(__file__).parents[4]
    cli_message = "Generic and regex analyzers do not support taint mode"
    for relpath in (
        "src/osemgrep/cli_scan/Scan_CLI.ml",
        "src/osemgrep/cli_test/Test_CLI.ml",
    ):
        help_text = _normalize_ocaml_string_text((repo_root / relpath).read_text())
        assert "fall back to intraprocedural analysis only" not in help_text
        assert cli_message in help_text

    engine_text = _normalize_ocaml_string_text(
        (repo_root / "src/engine/Match_tainting_mode.ml").read_text()
    )
    assert "may be limited to intraprocedural analysis only" not in engine_text
    assert "taint mode requires a dedicated parser" in engine_text
    assert "generic and regex analyzers do not support taint analysis" in engine_text


@pytest.mark.kinda_slow
def test_interfile_taint_language_matrix(run_semgrep_in_tmp: RunSemgrep):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_language_matrix.yaml",
        target_name="taint_interfile_language_matrix",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results_by_id = {result["check_id"]: result for result in output["results"]}

    assert set(output["interfile_languages_used"]) == {
        language for language, _path, _line in INTERFILE_LANGUAGE_MATRIX.values()
    }
    assert set(results_by_id) == set(INTERFILE_LANGUAGE_MATRIX)
    for check_id, (_language, path, line) in INTERFILE_LANGUAGE_MATRIX.items():
        assert results_by_id[check_id]["path"] == path
        assert results_by_id[check_id]["start"]["line"] == line


@pytest.mark.kinda_slow
def test_interfile_taint_parser_smoke_matrix(run_semgrep_in_tmp: RunSemgrep):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_parser_smoke.yaml",
        target_name="taint_interfile_parser_smoke",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results_by_id = {result["check_id"]: result for result in output["results"]}

    assert output["errors"] == []
    assert set(output["interfile_languages_used"]) == INTERFILE_PARSER_SMOKE_LANGUAGES
    assert set(results_by_id) == INTERFILE_PARSER_SMOKE_FINDINGS


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_imported_js_helpers(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_js.yaml",
        target_name="taint_interfile_js",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["JavaScript"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_js"
    assert results[0]["path"] == "targets/taint_interfile_js/app.js"
    assert results[0]["start"]["line"] == 8


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_commonjs_require(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_js_commonjs.yaml",
        target_name="taint_interfile_js_commonjs",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["JavaScript"]
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


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_imported_javascript_module_value(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_js_imported_value.yaml",
        target_name="taint_interfile_js_imported_value",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["JavaScript"]
    assert len(results) == 2
    assert {result["check_id"] for result in results} == {
        "rules.taint_interfile_js_imported_value"
    }
    assert {result["path"] for result in results} == {
        "targets/taint_interfile_js_imported_value/app.js",
        "targets/taint_interfile_js_imported_value/namespace_app.js",
    }
    assert {result["start"]["line"] for result in results} == {4}


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_imported_javascript_object_methods(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_js_object_method.yaml",
        target_name="taint_interfile_js_object_method",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["JavaScript"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_js_object_method"
    assert results[0]["path"] == "targets/taint_interfile_js_object_method/app.js"
    assert results[0]["start"]["line"] == 4


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_class_field_helper_instances(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_class_field_instance.yaml",
        target_name="taint_interfile_class_field_instance",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {"JavaScript", "TypeScript"}
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_class_field_instance_js",
            "targets/taint_interfile_class_field_instance/javascript/app.js",
            7,
        ),
        (
            "rules.taint_interfile_class_field_instance_ts",
            "targets/taint_interfile_class_field_instance/typescript/app.ts",
            7,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_constructor_assigned_helper_instances(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_constructor_field_instance.yaml",
        target_name="taint_interfile_constructor_field_instance",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {"JavaScript", "TypeScript"}
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_constructor_field_instance_js",
            "targets/taint_interfile_constructor_field_instance/javascript/app.js",
            9,
        ),
        (
            "rules.taint_interfile_constructor_field_instance_ts",
            "targets/taint_interfile_constructor_field_instance/typescript/app.ts",
            9,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_javascript_constructor_parameter_instances(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_js_constructor_parameter_instance.yaml",
        target_name="taint_interfile_js_constructor_parameter_instance",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["JavaScript"]
    assert len(results) == 1
    assert (
        results[0]["check_id"]
        == "rules.taint_interfile_js_constructor_parameter_instance"
    )
    assert (
        results[0]["path"]
        == "targets/taint_interfile_js_constructor_parameter_instance/app.js"
    )
    assert results[0]["start"]["line"] == 9


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_javascript_constructor_parameter_aliases(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_js_constructor_parameter_alias.yaml",
        target_name="taint_interfile_js_constructor_parameter_alias",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["JavaScript"]
    assert len(results) == 1
    assert (
        results[0]["check_id"]
        == "rules.taint_interfile_js_constructor_parameter_alias"
    )
    assert (
        results[0]["path"]
        == "targets/taint_interfile_js_constructor_parameter_alias/app.js"
    )
    assert results[0]["start"]["line"] == 9


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_typescript_parameter_properties(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_typescript_parameter_property.yaml",
        target_name="taint_interfile_typescript_parameter_property",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["TypeScript"]
    assert len(results) == 1
    assert (
        results[0]["check_id"]
        == "rules.taint_interfile_typescript_parameter_property"
    )
    assert (
        results[0]["path"]
        == "targets/taint_interfile_typescript_parameter_property/app.ts"
    )
    assert results[0]["start"]["line"] == 7


@pytest.mark.kinda_slow
def test_interfile_taint_applies_imported_javascript_sanitizers(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_js_sanitizer.yaml",
        target_name="taint_interfile_js_sanitizer",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["errors"] == []
    assert output["interfile_languages_used"] == ["JavaScript"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_js_sanitizer"
    assert results[0]["path"] == "targets/taint_interfile_js_sanitizer/app.js"
    assert results[0]["start"]["line"] == 6


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_imported_javascript_propagators(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_js_propagator.yaml",
        target_name="taint_interfile_js_propagator",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["errors"] == []
    assert output["interfile_languages_used"] == ["JavaScript"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_js_propagator"
    assert results[0]["path"] == "targets/taint_interfile_js_propagator/app.js"
    assert results[0]["start"]["line"] == 7


@pytest.mark.kinda_slow
def test_interfile_taint_keeps_imported_values_package_qualified(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_imported_value_package_collision.yaml",
        target_name="taint_interfile_imported_value_package_collision",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python", "JavaScript"]
    assert len(results) == 2
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_imported_value_package_collision_python",
            "targets/taint_interfile_imported_value_package_collision/python/app.py",
            6,
        ),
        (
            "rules.taint_interfile_imported_value_package_collision_js",
            "targets/taint_interfile_imported_value_package_collision/javascript/app.js",
            5,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_java_static_helpers(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_java.yaml",
        target_name="taint_interfile_java",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Java"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_java"
    assert results[0]["path"] == "targets/taint_interfile_java/App.java"
    assert results[0]["start"]["line"] == 3


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_python_imports(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python.yaml",
        target_name="taint_interfile_python",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_python"
    assert results[0]["path"] == "targets/taint_interfile_python/app.py"
    assert results[0]["start"]["line"] == 6


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_python_module_imports(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python_module_import.yaml",
        target_name="taint_interfile_python_module_import",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 2
    assert {result["path"] for result in results} == {
        "targets/taint_interfile_python_module_import/alias_app.py",
        "targets/taint_interfile_python_module_import/app.py",
    }
    assert {result["start"]["line"] for result in results} == {6}


@pytest.mark.kinda_slow
def test_interfile_taint_keeps_same_named_python_functions_separate(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python_duplicate_names.yaml",
        target_name="taint_interfile_python_duplicate_names",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 2
    assert {result["path"] for result in results} == {
        "targets/taint_interfile_python_duplicate_names/first.py",
        "targets/taint_interfile_python_duplicate_names/second.py",
    }
    assert {result["start"]["line"] for result in results} == {6}


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_imported_python_class_instance(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python_class_instance.yaml",
        target_name="taint_interfile_python_class_instance",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_python_class_instance"
    assert results[0]["path"] == "targets/taint_interfile_python_class_instance/app.py"
    assert results[0]["start"]["line"] == 7


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_inherited_python_methods(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python_inheritance.yaml",
        target_name="taint_interfile_python_inheritance",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_python_inheritance"
    assert results[0]["path"] == "targets/taint_interfile_python_inheritance/app.py"
    assert results[0]["start"]["line"] == 6


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_inherited_constructors(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_inherited_constructor.yaml",
        target_name="taint_interfile_inherited_constructor",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {"Java", "JavaScript", "Python"}
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_inherited_constructor_java",
            "targets/taint_interfile_inherited_constructor/java/App.java",
            4,
        ),
        (
            "rules.taint_interfile_inherited_constructor_js",
            "targets/taint_interfile_inherited_constructor/javascript/app.js",
            5,
        ),
        (
            "rules.taint_interfile_inherited_constructor_python",
            "targets/taint_interfile_inherited_constructor/python/app.py",
            6,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_unqualified_java_fields(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_java_unqualified_field.yaml",
        target_name="taint_interfile_java_unqualified_field",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Java"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_java_unqualified_field"
    assert results[0]["path"] == "targets/taint_interfile_java_unqualified_field/App.java"
    assert results[0]["start"]["line"] == 4


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_unqualified_instance_fields(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_unqualified_instance_field.yaml",
        target_name="taint_interfile_unqualified_instance_field",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {"C#", "Kotlin"}
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_unqualified_instance_field_csharp",
            "targets/taint_interfile_unqualified_instance_field/csharp/App.cs",
            4,
        ),
        (
            "rules.taint_interfile_unqualified_instance_field_kotlin",
            "targets/taint_interfile_unqualified_instance_field/kotlin/app.kt",
            3,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_static_fields(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_static_field.yaml",
        target_name="taint_interfile_static_field",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {"C#", "Java", "JavaScript"}
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_static_field_java",
            "targets/taint_interfile_static_field/java_unqualified/App.java",
            3,
        ),
        (
            "rules.taint_interfile_static_field_java",
            "targets/taint_interfile_static_field/java_qualified/App.java",
            3,
        ),
        (
            "rules.taint_interfile_static_field_csharp",
            "targets/taint_interfile_static_field/csharp_unqualified/App.cs",
            3,
        ),
        (
            "rules.taint_interfile_static_field_csharp",
            "targets/taint_interfile_static_field/csharp_qualified/App.cs",
            3,
        ),
        (
            "rules.taint_interfile_static_field_js",
            "targets/taint_interfile_static_field/javascript/app.js",
            4,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_callbacks(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_callback.yaml",
        target_name="taint_interfile_callback",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {"JavaScript", "Python"}
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_callback_js",
            "targets/taint_interfile_callback/javascript_return/app.js",
            3,
        ),
        (
            "rules.taint_interfile_callback_js",
            "targets/taint_interfile_callback/javascript_sink/app.js",
            3,
        ),
        (
            "rules.taint_interfile_callback_python",
            "targets/taint_interfile_callback/python_return/app.py",
            3,
        ),
        (
            "rules.taint_interfile_callback_python",
            "targets/taint_interfile_callback/python_sink/app.py",
            3,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_keeps_callback_imports_path_qualified(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_callback_collision.yaml",
        target_name="taint_interfile_callback_collision",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {"JavaScript", "Python"}
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_callback_collision_js",
            "targets/taint_interfile_callback_collision/javascript/first/app.js",
            3,
        ),
        (
            "rules.taint_interfile_callback_collision_js",
            "targets/taint_interfile_callback_collision/javascript/second/app.js",
            3,
        ),
        (
            "rules.taint_interfile_callback_collision_python",
            "targets/taint_interfile_callback_collision/python/first/app.py",
            3,
        ),
        (
            "rules.taint_interfile_callback_collision_python",
            "targets/taint_interfile_callback_collision/python/second/app.py",
            3,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_typed_callbacks(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_typed_callback.yaml",
        target_name="taint_interfile_typed_callback",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {"C#", "Java", "Kotlin"}
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_typed_callback_java",
            "targets/taint_interfile_typed_callback/java_return/AppReturn.java",
            3,
        ),
        (
            "rules.taint_interfile_typed_callback_java",
            "targets/taint_interfile_typed_callback/java_sink/AppSink.java",
            3,
        ),
        (
            "rules.taint_interfile_typed_callback_kotlin",
            "targets/taint_interfile_typed_callback/kotlin_return/app.kt",
            2,
        ),
        (
            "rules.taint_interfile_typed_callback_kotlin",
            "targets/taint_interfile_typed_callback/kotlin_sink/app.kt",
            2,
        ),
        (
            "rules.taint_interfile_typed_callback_csharp",
            "targets/taint_interfile_typed_callback/csharp_return/AppReturn.cs",
            3,
        ),
        (
            "rules.taint_interfile_typed_callback_csharp",
            "targets/taint_interfile_typed_callback/csharp_sink/AppSink.cs",
            3,
        ),
    }


@pytest.mark.kinda_slow
def test_interfile_taint_callback_language_matrix(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_callback_language_matrix.yaml",
        target_name="taint_interfile_callback_language_matrix",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {
        "Clojure",
        "Elixir",
        "PHP",
        "Ruby",
        "Rust",
        "Scala",
        "Swift",
    }
    assert {
        (result["check_id"], result["path"], result["start"]["line"])
        for result in results
    } == {
        (
            "rules.taint_interfile_callback_matrix_ruby",
            "targets/taint_interfile_callback_language_matrix/ruby/app.rb",
            2,
        ),
        (
            "rules.taint_interfile_callback_matrix_scala",
            "targets/taint_interfile_callback_language_matrix/scala/App.scala",
            1,
        ),
        (
            "rules.taint_interfile_callback_matrix_rust",
            "targets/taint_interfile_callback_language_matrix/rust/app.rs",
            1,
        ),
        (
            "rules.taint_interfile_callback_matrix_swift",
            "targets/taint_interfile_callback_language_matrix/swift/app.swift",
            1,
        ),
        (
            "rules.taint_interfile_callback_matrix_php",
            "targets/taint_interfile_callback_language_matrix/php/app.php",
            3,
        ),
        (
            "rules.taint_interfile_callback_matrix_elixir",
            "targets/taint_interfile_callback_language_matrix/elixir/app.ex",
            2,
        ),
        (
            "rules.taint_interfile_callback_matrix_clojure",
            "targets/taint_interfile_callback_language_matrix/clojure/app.clj",
            1,
        ),
    }


CALLBACK_BODY_LANGUAGE_MATRIX = {
    "rules.taint_interfile_callback_body_matrix_clojure": (
        "targets/taint_interfile_callback_body_language_matrix/clojure/app.clj",
        1,
    ),
    "rules.taint_interfile_callback_body_matrix_elixir": (
        "targets/taint_interfile_callback_body_language_matrix/elixir/app.ex",
        2,
    ),
    "rules.taint_interfile_callback_body_matrix_ruby": (
        "targets/taint_interfile_callback_body_language_matrix/ruby/app.rb",
        2,
    ),
    "rules.taint_interfile_callback_body_matrix_rust": (
        "targets/taint_interfile_callback_body_language_matrix/rust/app.rs",
        1,
    ),
    "rules.taint_interfile_callback_body_matrix_scala": (
        "targets/taint_interfile_callback_body_language_matrix/scala/App.scala",
        1,
    ),
    "rules.taint_interfile_callback_body_matrix_swift": (
        "targets/taint_interfile_callback_body_language_matrix/swift/app.swift",
        1,
    ),
}


@pytest.mark.kinda_slow
def test_interfile_taint_callback_body_language_matrix(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_callback_body_language_matrix.yaml",
        target_name="taint_interfile_callback_body_language_matrix",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert set(output["interfile_languages_used"]) == {
        "Clojure",
        "Elixir",
        "Ruby",
        "Rust",
        "Scala",
        "Swift",
    }
    assert {
        result["check_id"]: (result["path"], result["start"]["line"])
        for result in results
    } == CALLBACK_BODY_LANGUAGE_MATRIX


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_imported_python_module_value(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python_imported_value.yaml",
        target_name="taint_interfile_python_imported_value",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 3
    assert {result["check_id"] for result in results} == {
        "rules.taint_interfile_python_imported_value"
    }
    assert {result["path"] for result in results} == {
        "targets/taint_interfile_python_imported_value/app.py",
        "targets/taint_interfile_python_imported_value/module_app.py",
        "targets/taint_interfile_python_imported_value/reexport_app.py",
    }
    assert {result["start"]["line"] for result in results} == {5}


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_python_wildcard_imports(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python_wildcard_import.yaml",
        target_name="taint_interfile_python_wildcard_import",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 2
    assert {result["check_id"] for result in results} == {
        "rules.taint_interfile_python_wildcard_import"
    }
    assert {result["path"] for result in results} == {
        "targets/taint_interfile_python_wildcard_import/app.py",
        "targets/taint_interfile_python_wildcard_import/reexport_app.py",
    }
    assert {result["start"]["line"] for result in results} == {5}


@pytest.mark.kinda_slow
def test_interfile_taint_applies_imported_python_sanitizers(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python_sanitizer.yaml",
        target_name="taint_interfile_python_sanitizer",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_python_sanitizer"
    assert results[0]["path"] == "targets/taint_interfile_python_sanitizer/app.py"
    assert results[0]["start"]["line"] == 6


@pytest.mark.kinda_slow
def test_interfile_taint_applies_imported_python_side_effect_sanitizers(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_python_side_effect_sanitizer.yaml",
        target_name="taint_interfile_python_side_effect_sanitizer",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Python"]
    assert len(results) == 1
    assert results[0]["check_id"] == (
        "rules.taint_interfile_python_side_effect_sanitizer"
    )
    assert results[0]["path"] == (
        "targets/taint_interfile_python_side_effect_sanitizer/app.py"
    )
    assert results[0]["start"]["line"] == 10


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_go_package_functions(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_go.yaml",
        target_name="taint_interfile_go",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Go"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_go"
    assert results[0]["path"] == "targets/taint_interfile_go/app.go"
    assert results[0]["start"]["line"] == 4


@pytest.mark.kinda_slow
def test_interfile_taint_flows_through_elixir_module_calls(
    run_semgrep_in_tmp: RunSemgrep,
):
    stdout, _stderr = run_semgrep_in_tmp(
        "rules/taint_interfile_elixir.yaml",
        target_name="taint_interfile_elixir",
        output_format=OutputFormat.JSON,
    )

    output = json.loads(stdout)
    results = output["results"]

    assert output["interfile_languages_used"] == ["Elixir"]
    assert len(results) == 1
    assert results[0]["check_id"] == "rules.taint_interfile_elixir"
    assert results[0]["path"] == "targets/taint_interfile_elixir/app.ex"
    assert results[0]["start"]["line"] == 2
