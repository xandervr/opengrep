(* Yoann Padioleau
 *
 * Copyright (C) 2019-2023 r2c
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation, with the
 * special exception on linking described in file LICENSE.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the file
 * LICENSE for more details.
 *)
open Common
open Fpath_.Operators
open Pfff_or_tree_sitter

(*****************************************************************************)
(* Prelude *)
(*****************************************************************************)
(* Most of the code here used to be in Parse_target.ml, but was moved
 * to make the engine/ language independent so that we can generate
 * a smaller engine.js file.
 *
 * TODO: at some point maybe leverage Parsing_plugin instead of
 * modifying refs as currently done in Parsing_init.ml
 *)

(*****************************************************************************)
(* Helpers *)
(*****************************************************************************)

let lang_to_python_parsing_mode = function
  | Lang.Python -> Parse_python.Python
  | Lang.Python2 -> Parse_python.Python2
  | Lang.Python3 -> Parse_python.Python3
  | s -> failwith (spf "not a python language:%s" (Lang.to_string s))

let find_substring_from s needle start =
  let len = String.length s in
  let needle_len = String.length needle in
  let rec loop i =
    if i + needle_len > len then None
    else if String.equal (String.sub s i needle_len) needle then Some i
    else loop (i + 1)
  in
  loop start

let find_char_from s ch start =
  let len = String.length s in
  let rec loop i =
    if i >= len then None
    else if Char.equal s.[i] ch then Some i
    else loop (i + 1)
  in
  loop start

let blank_non_newlines contents =
  Bytes.init (String.length contents) (fun i ->
      match contents.[i] with
      | '\n'
      | '\r' ->
          contents.[i]
      | _ -> ' ')

let copy_range contents dest start stop =
  for i = start to stop - 1 do
    Bytes.set dest i contents.[i]
  done

let vue_script_contents contents =
  let lower = String.lowercase_ascii contents in
  let dest = blank_non_newlines contents in
  let rec loop search_pos =
    match find_substring_from lower "<script" search_pos with
    | None -> Bytes.unsafe_to_string dest
    | Some tag_start -> (
        match find_char_from lower '>' tag_start with
        | None -> Bytes.unsafe_to_string dest
        | Some tag_end ->
            let body_start = tag_end + 1 in
            let body_end, next_pos =
              match find_substring_from lower "</script>" body_start with
              | None -> (String.length contents, String.length contents)
              | Some close_start -> (close_start, close_start + 9)
            in
            copy_range contents dest body_start body_end;
            loop next_pos)
  in
  loop 0

let parse_vue_script file =
  let contents = UFile.read_file file |> vue_script_contents in
  run file
    [
      TreeSitter
        (fun _ ->
          Parse_typescript_tree_sitter.parse_string ~dialect:`TSX ~src_file:file
            contents);
    ]
    Js_to_generic.program

(*****************************************************************************)
(* Entry point *)
(*****************************************************************************)

let just_parse_with_lang lang file : Parsing_result2.t =

  match lang with
  (* Neither Menhir nor tree-sitter *)
  | Lang.Scala ->
      run file
        [ Pfff (throw_tokens Parse_scala.parse) ]
        Scala_to_generic.program
  | Lang.Yaml ->
      {
        ast = Yaml_to_generic.program file;
        errors = [];
        skipped_tokens = [];
        inserted_tokens = [];
        tolerated_errors = [];
        stat = Parsing_stat.default_stat !!file;
      }
  (* Menhir and Tree-sitter *)
  | Lang.C
  | Lang.Cpp ->
      run file
        [
          TreeSitter Parse_cpp_tree_sitter.parse;
          Pfff (throw_tokens Parse_cpp.parse);
        ]
        Cpp_to_generic.program
  | Lang.Go ->
      run file
        [
          TreeSitter Parse_go_tree_sitter.parse;
          Pfff (throw_tokens Parse_go.parse);
        ]
        Go_to_generic.program
  | Lang.Java ->
      run file
        [
          (* we used to start with the pfff one; it was quite good and faster
           * than tree-sitter (because we used to wrap tree-sitter inside
           * an invoke because of a segfault/memory-leak), but when both parsers
           * fail, it's better to give the tree-sitter parsing error now.
           *)
          TreeSitter Parse_java_tree_sitter.parse;
          Pfff (throw_tokens Parse_java.parse);
        ]
        Java_to_generic.program
  | Lang.Js ->
      (* we start directly with tree-sitter here, because
       * the pfff parser is slow on minified files due to its (slow) error
       * recovery strategy.
       *)
      run file
        [
          TreeSitter (Parse_typescript_tree_sitter.parse ~dialect:`TSX);
          Pfff (throw_tokens Parse_js.parse);
        ]
        Js_to_generic.program
  | Lang.Json ->
      run file
        [
          Pfff
            (fun file ->
              (Parse_json.parse_program file, Parsing_stat.correct_stat !!file));
        ]
        Json_to_generic.program
  | Lang.Ocaml ->
      run file
        [
          TreeSitter Parse_ocaml_tree_sitter.parse;
          Pfff (throw_tokens Parse_ml.parse);
        ]
        Ocaml_to_generic.program
  | Lang.Php ->
      run file
        [
          Pfff
            (fun file ->
              (* TODO: at some point parser_php.mly should go directly
               * to ast_php.ml and we should get rid of cst_php.ml
               *)
              let cst, stat = throw_tokens Parse_php.parse file in
              (Ast_php_build.program cst, stat));
          (* TODO: can't put TreeSitter first, because we still use Pfff
           * to parse the pattern, and there must be mismatch between the
           * AST generated by Ast_php_build and Parse_php_tree_sitter.parse.
           *)
          TreeSitter Parse_php_tree_sitter.parse;
        ]
        Php_to_generic.program
  | Lang.Python
  | Lang.Python2
  | Lang.Python3 ->
      let parsing_mode = lang_to_python_parsing_mode lang in
      run file
        [
          Pfff (throw_tokens (Parse_python.parse ~parsing_mode));
          TreeSitter Parse_python_tree_sitter.parse;
        ]
        Python_to_generic.program
  (* Tree-sitter only *)
  | Lang.Bash ->
      run file
        [ TreeSitter Parse_bash_tree_sitter.parse ]
        Bash_to_generic.program
  | Lang.Dockerfile ->
      run file
        [ TreeSitter Parse_dockerfile_tree_sitter.parse ]
        Dockerfile_to_generic.program
  | Lang.Jsonnet ->
      run file
        [ TreeSitter Parse_jsonnet_tree_sitter.parse ]
        Jsonnet_to_generic.program
  | Lang.Ql ->
      run file [ TreeSitter Parse_ql_tree_sitter.parse ] QL_to_generic.program
  | Lang.Terraform ->
      run file
        [ TreeSitter Parse_terraform_tree_sitter.parse ]
        Terraform_to_generic.program
  | Lang.Ts ->
      run file
        [ TreeSitter (Parse_typescript_tree_sitter.parse ?dialect:None) ]
        Js_to_generic.program
  | Lang.Vue -> parse_vue_script file
  (* there is no pfff parsers for C#/Kotlin/... so let's just use
   * tree-sitter, and there's no ast_xxx.ml either so we directly generate
   * a generic AST (no calls to an xxx_to_generic() below)
   *)
  | Lang.Cairo ->
      run file [ TreeSitter Parse_cairo_tree_sitter.parse ] (fun x -> x)
  | Lang.Ruby ->
      run file
        [ TreeSitter Parse_ruby_tree_sitter.parse ]
        Ruby_to_generic.program
  (* tree-sitter-dart is currently buggy and can generate some segfaults *)
  | Lang.Dart ->
      run file [ TreeSitter Parse_dart_tree_sitter.parse ] (fun x -> x)
  | Lang.Hack ->
      run file [ TreeSitter Parse_hack_tree_sitter.parse ] (fun x -> x)
  | Lang.Html
  (* TODO: there is now https://github.com/ObserverOfTime/tree-sitter-xml
   * which we could use for XML instead of abusing tree-sitter-html
   *)
  | Lang.Xml ->
      (* less: there is an html parser in pfff too we could use as backup *)
      run file [ TreeSitter Parse_html_tree_sitter.parse ] (fun x -> x)
  | Lang.Julia ->
      run file [ TreeSitter Parse_julia_tree_sitter.parse ] (fun x -> x)
  | Lang.Kotlin ->
      run file [ TreeSitter Parse_kotlin_tree_sitter.parse ] (fun x -> x)
  | Lang.Lisp
  | Lang.Scheme
  | Lang.Clojure ->
      run file [ TreeSitter Parse_clojure_tree_sitter.parse ] (fun x -> x)
  | Lang.Lua -> run file [ TreeSitter Parse_lua_tree_sitter.parse ] (fun x -> x)
  | Lang.Promql ->
      run file [ TreeSitter Parse_promql_tree_sitter.parse ] (fun x -> x)
  | Lang.Protobuf ->
      run file [ TreeSitter Parse_protobuf_tree_sitter.parse ] (fun x -> x)
  | Lang.Rust ->
      run file [ TreeSitter Parse_rust_tree_sitter.parse ] (fun x -> x)
  | Lang.Solidity ->
      run file [ TreeSitter Parse_solidity_tree_sitter.parse ] (fun x -> x)
  | Lang.Swift ->
      run file [ TreeSitter Parse_swift_tree_sitter.parse ] (fun x -> x)
  | Lang.R -> run file [ TreeSitter Parse_r_tree_sitter.parse ] (fun x -> x)
  | Lang.Move_on_sui ->
      run file [ TreeSitter Parse_move_on_sui_tree_sitter.parse ] (fun x -> x)
  | Lang.Move_on_aptos ->
      run file [ TreeSitter Parse_move_on_aptos_tree_sitter.parse ] (fun x -> x)
  | Lang.Circom ->
      run file [ TreeSitter Parse_circom_tree_sitter.parse ] (fun x -> x)
  (* this is how semgrep used to call Elixir right before they moved it into Pro. *)
  | Lang.Elixir ->
      run file
        [ TreeSitter Parse_elixir_tree_sitter.parse ]
        Elixir_to_generic.program
  | Lang.Apex ->
      run file [ TreeSitter Parse_apex_tree_sitter.parse ] (fun x -> x)
  | Lang.Csharp ->
      run file [ TreeSitter Parse_csharp_tree_sitter.parse ] (fun x -> x)
  (* Neither pfff nor tree-sitter. Can't use run, because it supports
   * "partial" for tree-sitter only. *)
  (* TODO: Move this block of code somewhere else. *)
  | Lang.Vb ->
      let make_res ast stat errs : Parsing_result2.t =
        Parsing_result2.{
            ast = ast;
            errors = errs;
            skipped_tokens = [];
            inserted_tokens = [];
            tolerated_errors = [];
            stat = stat
          }
      in
      let open Vbnet_parser in
      match Vbnet_parser.parse_file file with
      | Ok (ast, stat) ->
          make_res ast stat []
      | Partial (ast, stat, err) ->
          make_res ast stat
            (err
             |> Option.map (fun (f, s, p) -> Parsing_result2.Other_error (f, s, p))
             |> Option.to_list)
      | Fail (stat, err) ->
          make_res [] stat
            (err
             |> Option.map (fun (f, s, p) -> Parsing_result2.Other_error (f, s, p))
             |> Option.to_list)
