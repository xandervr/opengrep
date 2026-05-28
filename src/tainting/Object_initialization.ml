(* Object Initialization Detection for All Languages
 *
 * This module provides comprehensive object initialization detection
 * for all languages supported by Semgrep, enabling sophisticated
 * taint analysis across object constructors and method calls.
 *)

module G = AST_generic

(*****************************************************************************)
(* Types *)
(*****************************************************************************)

(* Object mapping: variable -> class *)
type object_mapping = G.name * G.name

type constructor_param_field_mapping = {
  class_name : string;
  field_name : G.name;
  param_index : int;
}

(* Matcher type: extracts class name from constructor expression *)
type matcher = G.expr -> G.name list -> G.name option

(*****************************************************************************)
(* Common Matchers *)
(*****************************************************************************)

(* Check if a name is in the known classes list *)
let is_known_class (name : G.name) (class_names : G.name list) : bool =
  List.exists
    (fun class_name ->
      match (name, class_name) with
      | G.Id ((str1, _), _), G.Id ((str2, _), _) -> str1 = str2
      | _ -> false)
    class_names

(* Check if string starts with uppercase *)
let is_uppercase_start str =
  String.length str > 0 && Char.uppercase_ascii str.[0] = str.[0]

let string_of_name = function
  | G.Id ((name, _), _) -> Some name
  | G.IdQualified { name_last = ((name, _), _); _ } -> Some name

let same_name name1 name2 =
  match (string_of_name name1, string_of_name name2) with
  | Some str1, Some str2 -> String.equal str1 str2
  | _ -> false

let same_resolved_name name1 name2 =
  match (name1, name2) with
  | G.Id ((str1, _), id_info1), G.Id ((str2, _), id_info2) ->
      String.equal str1 str2
      &&
      (match (!(id_info1.G.id_resolved), !(id_info2.G.id_resolved)) with
      | Some (_, sid1), Some (_, sid2) -> G.SId.equal sid1 sid2
      | _ -> true)
  | _ -> same_name name1 name2

(* Matcher: new ClassName(args) - basic form *)
let match_new_basic rval_expr class_names =
  match rval_expr.G.e with
  | G.New (_, class_type, _, _) -> (
      match class_type.G.t with
      | G.TyN name when is_known_class name class_names -> Some name
      | _ -> None)
  | _ -> None

(* Matcher: new ClassName(args) - with TyExpr fallback *)
let match_new_with_tyexpr rval_expr class_names =
  match rval_expr.G.e with
  | G.New (_, class_type, _, _) -> (
      match class_type.G.t with
      | G.TyN name when is_known_class name class_names -> Some name
      | G.TyExpr expr -> (
          match expr.G.e with
          | G.N (G.Id ((_, _), _) as name) when is_known_class name class_names ->
              Some name
          | _ -> None)
      | _ -> None)
  | _ -> None

(* Matcher: ClassName(args) - call with uppercase class name *)
let match_call_uppercase rval_expr class_names =
  match rval_expr.G.e with
  | G.Call (class_expr, _) -> (
      match class_expr.G.e with
      | G.N (G.Id ((str, _), _) as name)
        when is_uppercase_start str && is_known_class name class_names ->
          Some name
      | _ -> None)
  | _ -> None

(* Matcher: ClassName.new(args) - Ruby/Rust style *)
let match_dot_new rval_expr class_names =
  match rval_expr.G.e with
  | G.Call (dot_access, _) -> (
      match dot_access.G.e with
      | G.DotAccess (class_expr, _, G.FN (G.Id (("new", _), _))) -> (
          match class_expr.G.e with
          | G.N name when is_known_class name class_names -> Some name
          | _ -> None)
      | _ -> None)
  | _ -> None

(* Matcher: Go &Struct{} or Struct{} *)
let match_go_struct rval_expr class_names =
  match rval_expr.G.e with
  | G.Ref (_, struct_expr) -> (
      match struct_expr.G.e with
      | G.New (_, struct_type, _, _) -> (
          match struct_type.G.t with
          | G.TyN name when is_known_class name class_names -> Some name
          | _ -> None)
      | _ -> None)
  | G.New (_, struct_type, _, _) -> (
      match struct_type.G.t with
      | G.TyN name when is_known_class name class_names -> Some name
      | _ -> None)
  | _ -> None

(* Combine multiple matchers - try each until one succeeds *)
let combine matchers rval_expr class_names =
  List.find_map (fun m -> m rval_expr class_names) matchers

(* Apex: doesn't validate against class_names *)
let match_apex rval_expr _class_names =
  match rval_expr.G.e with
  | G.New (_, class_type, _, _) -> (
      match class_type.G.t with
      | G.TyN name -> Some name
      | _ -> None)
  | _ -> None

(*****************************************************************************)
(* Language Matcher Lookup *)
(*****************************************************************************)

let get_matcher (lang : Lang.t) : matcher option =
  match lang with
  | Lang.Java | Lang.Csharp | Lang.Vb -> Some match_new_basic
  | Lang.Php -> Some match_new_with_tyexpr
  | Lang.Python | Lang.Python2 | Lang.Python3 | Lang.Swift -> Some match_call_uppercase
  | Lang.Ruby | Lang.Rust -> Some match_dot_new
  | Lang.Go -> Some match_go_struct
  | Lang.Apex -> Some match_apex
  | Lang.Kotlin | Lang.Cpp -> Some (combine [match_new_basic; match_call_uppercase])
  | Lang.Scala | Lang.Js | Lang.Ts | Lang.Dart -> Some (combine [match_new_with_tyexpr; match_call_uppercase])
  | _ -> None

(*****************************************************************************)
(* Class Detection *)
(*****************************************************************************)

(* Collect all class names from the AST *)
let collect_class_names (ast : G.program) : G.name list =
  let class_names = ref [] in
  let visitor =
    object
      inherit [_] G.iter as super

      method! visit_definition () def =
        (match def with
        | entity, G.ClassDef _ -> (
            match entity.G.name with
            | G.EN name -> class_names := name :: !class_names
            | _ -> ())
        (* Handle Go struct definitions - TypeDef with TyRecordAnon *)
        | entity, G.TypeDef type_def -> (
            match (entity.G.name, type_def.G.tbody) with
            | G.EN name, G.NewType { G.t = G.TyRecordAnon ((G.Class, _), _); _ }
              ->
                class_names := name :: !class_names
            | _ -> ())
        | _ -> ());
        super#visit_definition () def
    end
  in

  List.iter
    (fun item ->
      match item.G.s with
      | G.DefStmt def -> visitor#visit_definition () def
      | _ -> ())
    ast;
  !class_names

(*****************************************************************************)
(* Object Initialization Detection *)
(*****************************************************************************)

(* Extract class name from constructor call expression *)
let extract_class_name_from_constructor (rval_expr : G.expr) (lang : Lang.t)
    (class_names : G.name list) : G.name option =
  match get_matcher lang with
  | Some matcher -> matcher rval_expr class_names
  | None -> None

(* Object initialization detection for different languages *)
let detect_object_initialization (ast : G.program) (lang : Lang.t) :
    object_mapping list =
  let class_names = collect_class_names ast in
  let object_mappings = ref [] in
  let object_property_mappings = ref [] in
  let object_property_alias_mappings = ref [] in
  let constructor_param_field_mappings = ref [] in
  let function_return_mappings = ref [] in
  let function_return_object_property_mappings = ref [] in
  let function_alias_mappings = ref [] in
  let object_property_factory_return_mappings = ref [] in
  let object_property_function_mappings = ref [] in
  let class_name_from_type (type_ : G.type_) =
    match type_.G.t with
    | G.TyN name when is_known_class name class_names -> Some name
    | G.TyExpr { G.e = G.N (G.Id _ as name); _ }
      when is_known_class name class_names ->
        Some name
    | _ -> None
  in
  let is_parameter_property_attr = function
    | G.KeywordAttr ((G.Public | G.Private | G.Protected | G.Const), _) -> true
    | _ -> false
  in
  let is_constructor_name func_name class_name =
    let config = Lang_config.get lang in
    List.mem func_name config.constructor_names || func_name = class_name
  in
  let constructor_arg_expr args index =
    let positional_args =
      args
      |> List.filter_map (function
           | G.Arg expr -> Some expr
           | _ -> None)
    in
    List.nth_opt positional_args index
  in
  let name_from_mapping mappings expr =
    match expr.G.e with
    | G.N name ->
        !mappings
        |> List.find_opt (fun (mapped_name, _resolved_name) ->
               same_resolved_name name mapped_name)
        |> Option.map snd
    | _ -> None
  in
  let name_from_called_function mappings func_expr =
    match func_expr.G.e with
    | G.Call ({ e = G.N name; _ }, _) ->
        !mappings
        |> List.find_opt (fun (mapped_name, _resolved_name) ->
               same_resolved_name name mapped_name)
        |> Option.map snd
    | _ -> None
  in
  let name_from_name_mapping mappings name =
    !mappings
    |> List.find_opt (fun (mapped_name, _resolved_name) ->
           same_resolved_name name mapped_name)
    |> Option.map snd
  in
  let same_resolved_path path1 path2 =
    List.length path1 = List.length path2
    && List.for_all2 same_resolved_name path1 path2
  in
  let rec object_property_path_from_expr expr =
    match expr.G.e with
    | G.DotAccess (obj_expr, _, G.FN field_name) -> (
        match object_property_path_from_expr obj_expr with
        | Some (obj_name, field_path) ->
            Some (obj_name, field_path @ [ field_name ])
        | None -> (
            match obj_expr.G.e with
            | G.N obj_name -> Some (obj_name, [ field_name ])
            | _ -> None))
    | _ -> None
  in
  let class_name_from_object_mapping expr =
    name_from_mapping object_mappings expr
  in
  let class_name_from_object_property_mapping expr =
    match object_property_path_from_expr expr with
    | Some (obj_name, field_path) ->
        !object_property_mappings
        |> List.find_opt (fun (mapped_obj, mapped_path, _class_name) ->
               same_resolved_name obj_name mapped_obj
               && same_resolved_path field_path mapped_path)
        |> Option.map (fun (_obj_name, _field_path, class_name) -> class_name)
    | None -> None
  in
  let class_name_from_direct_object_property_factory obj_name field_path =
    !object_property_factory_return_mappings
    |> List.find_opt (fun (mapped_obj, mapped_path, _class_name) ->
           same_resolved_name obj_name mapped_obj
           && same_resolved_path field_path mapped_path)
    |> Option.map (fun (_obj_name, _field_path, class_name) -> class_name)
  in
  let function_name_from_object_property_factory obj_name field_path =
    !object_property_function_mappings
    |> List.find_opt (fun (mapped_obj, mapped_path, _func_name) ->
           same_resolved_name obj_name mapped_obj
           && same_resolved_path field_path mapped_path)
    |> Option.map (fun (_obj_name, _field_path, func_name) -> func_name)
  in
  let function_has_returned_object_properties func_name =
    !function_return_object_property_mappings
    |> List.exists (fun (mapped_func_name, _mapped_path, _class_name) ->
           same_resolved_name func_name mapped_func_name)
  in
  let rec returned_object_property_function_names seen func_name =
    if List.exists (same_resolved_name func_name) seen then []
    else
      let direct_names =
        if function_has_returned_object_properties func_name then [ func_name ]
        else []
      in
      let alias_names =
        match name_from_name_mapping function_alias_mappings func_name with
        | Some aliased_func ->
            returned_object_property_function_names (func_name :: seen)
              aliased_func
        | None -> []
      in
      direct_names @ alias_names
  in
  let returned_object_property_function_names_from_callee callee_expr =
    let function_names_from_name name =
      returned_object_property_function_names [] name
    in
    match callee_expr.G.e with
    | G.N func_name -> function_names_from_name func_name
    | _ -> (
        match object_property_path_from_expr callee_expr with
        | Some (obj_name, field_path) -> (
            match function_name_from_object_property_factory obj_name field_path with
            | Some func_name -> function_names_from_name func_name
            | None -> [])
        | None -> [])
  in
  let class_name_from_direct_object_property_factory_expr expr =
    match object_property_path_from_expr expr with
    | Some (obj_name, field_path) ->
        class_name_from_direct_object_property_factory obj_name field_path
    | None -> None
  in
  let class_name_from_object_property_function_mapping callee_expr =
    match object_property_path_from_expr callee_expr with
    | Some (obj_name, field_path) ->
        (match class_name_from_direct_object_property_factory obj_name field_path with
        | Some _ as class_name -> class_name
        | None -> (
            match function_name_from_object_property_factory obj_name field_path with
            | Some func_name ->
                name_from_name_mapping function_return_mappings func_name
            | None -> None))
    | None -> None
  in
  let object_property_path_from_alias alias_name =
    let rec aux seen alias_name =
      if List.exists (same_resolved_name alias_name) seen then None
      else
        !object_property_alias_mappings
        |> List.find_opt (fun (mapped_alias, _obj_name, _field_path) ->
               same_resolved_name alias_name mapped_alias)
        |> Option.map (fun (_mapped_alias, obj_name, field_path) ->
               match aux (alias_name :: seen) obj_name with
               | Some (root_obj_name, root_field_path) ->
                   (root_obj_name, root_field_path @ field_path)
               | None -> (obj_name, field_path))
    in
    aux [] alias_name
  in
  let class_name_from_function_return expr =
    let class_name_from_function_alias () =
      match name_from_called_function function_alias_mappings expr with
      | Some returned_func ->
          name_from_name_mapping function_return_mappings returned_func
      | None -> (
          match expr.G.e with
          | G.Call (callee_expr, _) -> (
              match name_from_called_function function_alias_mappings callee_expr with
              | Some returned_func ->
                  name_from_name_mapping function_return_mappings returned_func
              | None -> None)
          | _ -> None)
    in
    match name_from_called_function function_return_mappings expr with
    | Some _ as class_name -> class_name
    | None -> (
        match expr.G.e with
        | G.Call (callee_expr, _) -> (
            match class_name_from_object_property_function_mapping callee_expr with
            | Some _ as class_name -> class_name
            | None -> class_name_from_function_alias ())
        | _ -> class_name_from_function_alias ())
  in
  let function_alias_from_expr expr =
    match name_from_called_function function_alias_mappings expr with
    | Some _ as returned_func -> returned_func
    | None -> (
        match expr.G.e with
        | G.N name -> (
            match name_from_name_mapping function_alias_mappings name with
            | Some _ as returned_func -> returned_func
            | None -> (
                match name_from_name_mapping function_return_mappings name with
                | Some _ -> Some name
                | None ->
                    if function_has_returned_object_properties name then Some name
                    else None))
        | _ -> (
            match object_property_path_from_expr expr with
            | Some (obj_name, field_path) ->
                function_name_from_object_property_factory obj_name field_path
            | None -> None))
  in
  let record_function_alias_mapping alias_name init_expr =
    match function_alias_from_expr init_expr with
    | Some returned_func ->
        function_alias_mappings :=
          (alias_name, returned_func) :: !function_alias_mappings
    | None -> (
        match class_name_from_direct_object_property_factory_expr init_expr with
        | Some class_name ->
            function_return_mappings :=
              (alias_name, class_name) :: !function_return_mappings
        | None -> ())
  in
  let rec class_name_from_expr expr =
    match extract_class_name_from_constructor expr lang class_names with
    | Some _ as class_name -> class_name
    | None -> (
        match class_name_from_object_mapping expr with
        | Some _ as class_name -> class_name
        | None -> (
            match class_name_from_object_property_mapping expr with
            | Some _ as class_name -> class_name
            | None -> (
                match class_name_from_function_return expr with
                | Some _ as class_name -> class_name
                | None -> class_name_from_conditional_expr expr)))
  and class_name_from_conditional_expr expr =
    match expr.G.e with
    | G.Conditional (_condition, then_expr, else_expr) -> (
        match (class_name_from_expr then_expr, class_name_from_expr else_expr) with
        | Some then_class, Some else_class when same_name then_class else_class
          ->
            Some then_class
        | _ -> None)
    | _ -> None
  in
  let record_constructor_param_field_mappings class_name fdef =
    let param_indexes =
      Tok.unbracket fdef.G.fparams
      |> List.mapi (fun index -> function
           | G.Param { G.pname = Some ((param_name, _)); _ } ->
               Some (param_name, index)
           | _ -> None)
      |> List.filter_map Fun.id
    in
    let param_index param_name = List.assoc_opt param_name param_indexes in
    let visitor =
      object
        inherit [_] G.iter as super

        method! visit_expr () expr =
          (match expr.G.e with
          | G.Assign
              ( { e =
                    G.DotAccess
                      ( { e = G.IdSpecial ((G.This | G.Self), _); _ },
                        _,
                        G.FN (G.Id _ as field_name) );
                  _ },
                _,
                { e = G.N (G.Id ((param_name, _), _)); _ } ) -> (
              match param_index param_name with
              | Some index ->
                  constructor_param_field_mappings :=
                    { class_name; field_name; param_index = index }
                    :: !constructor_param_field_mappings
              | None -> ())
          | _ -> ());
          super#visit_expr () expr
      end
    in
    visitor#visit_function_definition () fdef
  in
  let record_class_constructor_param_field_mappings class_name class_def =
    let class_name_str = string_of_name class_name in
    match class_name_str with
    | None -> ()
    | Some class_name_str ->
        Tok.unbracket class_def.G.cbody
        |> List.iter (function
             | G.F { G.s = G.DefStmt (entity, G.FuncDef fdef); _ } -> (
                 match entity.G.name with
                 | G.EN (G.Id ((func_name, _), _))
                   when is_constructor_name func_name class_name_str ->
                     record_constructor_param_field_mappings class_name_str fdef
                 | _ -> ())
             | _ -> ())
  in
  let record_constructor_argument_mappings class_name args =
    match string_of_name class_name with
    | None -> ()
    | Some class_name_str ->
        !constructor_param_field_mappings
        |> List.iter (fun mapping ->
               if mapping.class_name = class_name_str then
                 match constructor_arg_expr args mapping.param_index with
                 | Some arg_expr -> (
                     match class_name_from_expr arg_expr with
                     | Some arg_class ->
                         object_mappings :=
                           (mapping.field_name, arg_class) :: !object_mappings
                     | None -> ())
                 | None -> ())
  in
  let class_name_from_lambda_return fdef =
    let class_name = ref None in
    let visitor =
      object
        inherit [_] G.iter as super

        method! visit_stmt () stmt =
          (match (!class_name, stmt.G.s) with
          | None, G.Return (_, Some return_expr, _) ->
              class_name := class_name_from_expr return_expr
          | _ -> ());
          super#visit_stmt () stmt
      end
    in
    visitor#visit_stmt () (AST_generic_helpers.funcbody_to_stmt fdef.G.fbody);
    !class_name
  in
  let record_object_property_mappings obj_name init_expr =
    match init_expr.G.e with
    | G.Call (callee_expr, _) ->
        let returned_property_func_names =
          returned_object_property_function_names_from_callee callee_expr
        in
        !function_return_object_property_mappings
        |> List.iter
             (fun (mapped_func_name, mapped_path, class_name) ->
               if
                 List.exists
                   (fun func_name ->
                     same_resolved_name func_name mapped_func_name)
                   returned_property_func_names
               then
                 object_property_mappings :=
                   (obj_name, mapped_path, class_name)
                   :: !object_property_mappings)
    | G.Record (_, fields, _) ->
        let copy_spread_properties source_name =
          !object_property_mappings
          |> List.iter (fun (mapped_obj, mapped_path, class_name) ->
                 if same_resolved_name source_name mapped_obj then
                   object_property_mappings :=
                     (obj_name, mapped_path, class_name)
                     :: !object_property_mappings)
        in
        let rec record_fields field_path fields =
          fields
          |> List.iter (function
             | G.F
                 {
                   G.s =
                     G.DefStmt
                       ( field_entity,
                         G.FieldDefColon { G.vinit = Some field_init; _ } );
                   _;
                 } -> (
                 match field_entity.G.name with
                 | G.EN field_name -> (
                     let field_path = field_path @ [ field_name ] in
                     match class_name_from_expr field_init with
                     | Some class_name ->
                         object_property_mappings :=
                           (obj_name, field_path, class_name)
                           :: !object_property_mappings
                     | None -> ();
                     (match function_alias_from_expr field_init with
                     | Some func_name ->
                         object_property_function_mappings :=
                           (obj_name, field_path, func_name)
                           :: !object_property_function_mappings
                     | None -> ());
                     (match
                        class_name_from_direct_object_property_factory_expr
                          field_init
                      with
                     | Some class_name ->
                         object_property_factory_return_mappings :=
                           (obj_name, field_path, class_name)
                           :: !object_property_factory_return_mappings
                     | None -> ());
                     (match field_init.G.e with
                     | G.Lambda fdef -> (
                         match class_name_from_lambda_return fdef with
                         | Some class_name ->
                             object_property_factory_return_mappings :=
                               (obj_name, field_path, class_name)
                               :: !object_property_factory_return_mappings
                         | None -> ())
                     | _ -> ());
                     match field_init.G.e with
                     | G.Record (_, nested_fields, _) ->
                         record_fields field_path nested_fields
                     | _ -> ())
                 | _ -> ())
             | G.F
                 {
                   G.s =
                     G.ExprStmt
                       ( {
                           G.e =
                             G.Call
                               ( { G.e = G.IdSpecial (G.Spread, _); _ },
                                 ( _,
                                   [ G.Arg { G.e = G.N source_name; _ } ],
                                   _ ) );
                           _;
                         },
                         _ );
                   _;
                 } ->
                 copy_spread_properties source_name
             | _ -> ())
        in
        record_fields [] fields
    | _ -> ()
  in
  let record_object_property_assignment_mapping lval_expr rval_expr =
    let record_for_alias add_mapping obj_name field_path value =
        (match object_property_path_from_alias obj_name with
        | Some (root_obj_name, root_field_path) ->
            add_mapping root_obj_name (root_field_path @ field_path) value
        | None -> ())
    in
    let add_object_mapping obj_name field_path class_name =
      object_property_mappings :=
        (obj_name, field_path, class_name) :: !object_property_mappings
    in
    let add_function_mapping obj_name field_path func_name =
      object_property_function_mappings :=
        (obj_name, field_path, func_name) :: !object_property_function_mappings
    in
    let add_factory_return_mapping obj_name field_path class_name =
      object_property_factory_return_mappings :=
        (obj_name, field_path, class_name)
        :: !object_property_factory_return_mappings
    in
    let class_name_from_factory_expr expr =
      match class_name_from_direct_object_property_factory_expr expr with
      | Some _ as class_name -> class_name
      | None -> (
          match expr.G.e with
          | G.Lambda fdef -> class_name_from_lambda_return fdef
          | _ -> None)
    in
    match object_property_path_from_expr lval_expr with
    | Some (obj_name, field_path) ->
        (match class_name_from_expr rval_expr with
        | Some class_name ->
            add_object_mapping obj_name field_path class_name;
            record_for_alias add_object_mapping obj_name field_path class_name
        | None -> ());
        (match function_alias_from_expr rval_expr with
        | Some func_name ->
            add_function_mapping obj_name field_path func_name;
            record_for_alias add_function_mapping obj_name field_path func_name
        | None -> ());
        (match class_name_from_factory_expr rval_expr with
        | Some class_name ->
            add_factory_return_mapping obj_name field_path class_name;
            record_for_alias add_factory_return_mapping obj_name field_path
              class_name
        | None -> ())
    | None -> ()
  in
  let record_object_property_alias_mapping alias_name init_expr =
    match object_property_path_from_expr init_expr with
    | Some (obj_name, field_path) ->
        object_property_alias_mappings :=
          (alias_name, obj_name, field_path) :: !object_property_alias_mappings
    | None -> ()
  in
  let record_destructured_object_property_mappings init_expr =
    let local_name_from_field_init field_name = function
      | Some { G.e = G.N local_name; _ } -> Some local_name
      | Some _ -> None
      | None -> Some field_name
    in
    let top_level_field_in excluded_fields = function
      | field_name :: _ ->
          List.exists (same_resolved_name field_name) excluded_fields
      | [] -> false
    in
    let object_property_entries_from_expr source_expr =
      match source_expr.G.e with
      | G.N obj_name ->
          !object_property_mappings
          |> List.filter_map
               (fun (mapped_obj, mapped_path, class_name) ->
                 if same_resolved_name obj_name mapped_obj then
                   Some (mapped_path, class_name)
                 else None)
      | G.Call (callee_expr, _) ->
          let returned_property_func_names =
            returned_object_property_function_names_from_callee callee_expr
          in
          !function_return_object_property_mappings
          |> List.filter_map
               (fun (mapped_func_name, mapped_path, class_name) ->
                 if
                   List.exists
                     (fun func_name ->
                       same_resolved_name func_name mapped_func_name)
                     returned_property_func_names
                 then Some (mapped_path, class_name)
                 else None)
      | _ -> []
    in
    let class_name_from_source_object_property source_expr field_name =
      object_property_entries_from_expr source_expr
      |> List.find_opt (fun (mapped_path, _class_name) ->
             same_resolved_path [ field_name ] mapped_path)
      |> Option.map snd
    in
    let copy_rest_properties source_expr rest_name excluded_fields =
      object_property_entries_from_expr source_expr
      |> List.iter (fun (mapped_path, class_name) ->
             if not (top_level_field_in excluded_fields mapped_path) then
               object_property_mappings :=
                 (rest_name, mapped_path, class_name)
                 :: !object_property_mappings)
    in
    match init_expr.G.e with
    | G.Assign ({ e = G.Record (_, fields, _); _ }, _, source_expr)
      ->
        let destructured_fields =
          fields
          |> List.filter_map (function
               | G.F
                   {
                     G.s =
                       G.DefStmt
                         ( field_entity,
                           G.FieldDefColon { G.vinit = _; _ } );
                     _;
                   } -> (
                   match field_entity.G.name with
                   | G.EN field_name -> Some field_name
                   | _ -> None)
               | _ -> None)
        in
        fields
        |> List.iter (function
             | G.F
                 {
                   G.s =
                     G.DefStmt
                       ( field_entity,
                         G.FieldDefColon { G.vinit = field_init; _ } );
                   _;
                 } -> (
                 match field_entity.G.name with
                 | G.EN field_name -> (
                     match
                       ( local_name_from_field_init field_name field_init,
                         class_name_from_source_object_property source_expr
                           field_name
                       )
                     with
                     | Some local_name, Some class_name ->
                         object_mappings :=
                           (local_name, class_name) :: !object_mappings
                     | _ -> ())
                 | _ -> ())
             | G.F
                 {
                   G.s =
                     G.ExprStmt
                       ( {
                           G.e =
                             G.Call
                               ( { G.e = G.IdSpecial (G.Spread, _); _ },
                                 ( _,
                                   [ G.Arg { G.e = G.N rest_name; _ } ],
                                   _ ) );
                           _;
                         },
                         _ );
                   _;
                 } ->
                 copy_rest_properties source_expr rest_name destructured_fields
             | _ -> ())
    | _ -> ()
  in
  let record_function_return_mapping func_name fdef =
    let local_object_mappings = ref [] in
    let local_object_property_mappings = ref [] in
    let rec class_name_from_return_expr expr =
      match extract_class_name_from_constructor expr lang class_names with
      | Some _ as class_name -> class_name
      | None -> (
          match name_from_mapping local_object_mappings expr with
          | Some _ as class_name -> class_name
          | None -> (
              match class_name_from_function_return expr with
              | Some _ as class_name -> class_name
              | None -> class_name_from_return_conditional_expr expr))
    and class_name_from_return_conditional_expr expr =
      match expr.G.e with
      | G.Conditional (_condition, then_expr, else_expr) -> (
          match
            ( class_name_from_return_expr then_expr,
              class_name_from_return_expr else_expr )
          with
          | Some then_class, Some else_class when same_name then_class else_class
            ->
              Some then_class
          | _ -> None)
      | _ -> None
    in
    let record_local_object_mapping var_name init_expr =
      match class_name_from_return_expr init_expr with
      | Some class_name ->
          local_object_mappings := (var_name, class_name) :: !local_object_mappings
      | None -> ()
    in
    let rec record_returned_record_fields field_path fields =
      fields
      |> List.iter (function
           | G.F
               {
                 G.s =
                   G.DefStmt
                     ( field_entity,
                       G.FieldDefColon { G.vinit = Some field_init; _ } );
                 _;
               } -> (
               match field_entity.G.name with
               | G.EN field_name ->
                   let field_path = field_path @ [ field_name ] in
                   (match class_name_from_return_expr field_init with
                   | Some class_name ->
                       function_return_object_property_mappings :=
                         (func_name, field_path, class_name)
                         :: !function_return_object_property_mappings
                   | None -> ());
                   (match field_init.G.e with
                   | G.Record (_, nested_fields, _) ->
                       record_returned_record_fields field_path nested_fields
                   | _ -> ())
               | _ -> ())
           | _ -> ())
    in
    let record_returned_object_properties return_expr =
      match return_expr.G.e with
      | G.Record (_, fields, _) -> record_returned_record_fields [] fields
      | G.N local_name ->
          !local_object_property_mappings
          |> List.iter
               (fun (mapped_local_name, mapped_path, class_name) ->
                 if same_resolved_name local_name mapped_local_name then
                   function_return_object_property_mappings :=
                     (func_name, mapped_path, class_name)
                     :: !function_return_object_property_mappings)
      | _ -> ()
    in
    let record_local_object_property_mappings var_name init_expr =
      match init_expr.G.e with
      | G.Record (_, fields, _) ->
          let rec record_fields field_path fields =
            fields
            |> List.iter (function
                 | G.F
                     {
                       G.s =
                         G.DefStmt
                           ( field_entity,
                             G.FieldDefColon { G.vinit = Some field_init; _ } );
                       _;
                     } -> (
                     match field_entity.G.name with
                     | G.EN field_name ->
                         let field_path = field_path @ [ field_name ] in
                         (match class_name_from_return_expr field_init with
                         | Some class_name ->
                             local_object_property_mappings :=
                               (var_name, field_path, class_name)
                               :: !local_object_property_mappings
                         | None -> ());
                         (match field_init.G.e with
                         | G.Record (_, nested_fields, _) ->
                             record_fields field_path nested_fields
                         | _ -> ())
                     | _ -> ())
                 | _ -> ())
          in
          record_fields [] fields
      | _ -> ()
    in
    let visitor =
      object
        inherit [_] G.iter as super

        method! visit_stmt () stmt =
          (match stmt.G.s with
          | G.DefStmt (entity, G.VarDef { G.vinit = Some init_expr; _ }) -> (
              match entity.G.name with
              | G.EN var_name ->
                  record_local_object_mapping var_name init_expr;
                  record_local_object_property_mappings var_name init_expr
              | _ -> ())
          | G.ExprStmt ({ G.e = G.Assign ({ G.e = G.N var_name; _ }, _, rval_expr); _ }, _) ->
              record_local_object_mapping var_name rval_expr
          | G.Return (_, Some return_expr, _) -> (
              record_returned_object_properties return_expr;
              match class_name_from_return_expr return_expr with
              | Some class_name ->
                  function_return_mappings :=
                    (func_name, class_name) :: !function_return_mappings
              | None -> (
                  match return_expr.G.e with
                  | G.N returned_func ->
                      function_alias_mappings :=
                        (func_name, returned_func) :: !function_alias_mappings
                  | _ -> ()))
          | _ -> ());
          super#visit_stmt () stmt
      end
    in
    visitor#visit_function_definition () fdef
  in
  let function_return_visitor =
    object
      inherit [_] G.iter as super

      method! visit_definition () def =
        (match def with
        | entity, G.FuncDef fdef -> (
            match entity.G.name with
            | G.EN func_name -> record_function_return_mapping func_name fdef
            | _ -> ())
        | entity, G.VarDef { G.vinit = Some { G.e = G.Lambda fdef; _ }; _ }
          -> (
            match entity.G.name with
            | G.EN func_name -> record_function_return_mapping func_name fdef
            | _ -> ())
        | _ -> ());
        super#visit_definition () def
    end
  in

  let visitor =
    object
      inherit [_] G.iter as super

      method! visit_expr () expr =
        (match expr.G.e with
        | G.New (_, class_type, _, args) -> (
            match class_type.G.t with
            | G.TyN class_name
            | G.TyExpr { G.e = G.N class_name; _ } ->
                record_constructor_argument_mappings class_name
                  (Tok.unbracket args)
            | _ -> ())
        | _ -> ());
        super#visit_expr () expr

      method! visit_stmt () stmt =
        (match stmt.G.s with
        | G.DefStmt (entity, def_kind) -> (
            match def_kind with
            | G.VarDef var_def -> (
                match (entity.G.name, var_def.G.vinit) with
                | G.EN var_name, Some init_expr -> (
                    record_object_property_mappings var_name init_expr;
                    record_object_property_alias_mapping var_name init_expr;
                    record_destructured_object_property_mappings init_expr;
                    record_function_alias_mapping var_name init_expr;
                    let class_name = class_name_from_expr init_expr in
                    let class_name =
                      match (class_name, lang) with
                      | Some cls, _ -> Some cls
                      | None, Lang.Cpp -> (
                          match var_def.G.vtype with
                          | Some var_type -> (
                              match var_type.G.t with
                              | G.TyN name when is_known_class name class_names
                                ->
                                  Some name
                              | _ -> None)
                          | None -> None)
                      | None, _ -> None
                    in
                    match class_name with
                    | Some cls ->
                        object_mappings := (var_name, cls) :: !object_mappings
                    | _ -> ())
                | G.EN var_name, None when lang = Lang.Cpp -> (
                    match var_def.G.vtype with
                    | Some var_type -> (
                        match var_type.G.t with
                        | G.TyN name when is_known_class name class_names ->
                            object_mappings :=
                              (var_name, name) :: !object_mappings
                        | G.TyFun (_, return_type) -> (
                            match return_type.G.t with
                            | G.TyN name when is_known_class name class_names ->
                                object_mappings :=
                                  (var_name, name) :: !object_mappings
                            | _ -> ())
                        | _ -> ())
                    | None -> ())
                | _ -> ())
            | _ -> ())
        | G.ExprStmt (expr, _) -> (
            match expr.G.e with
            | G.Assign (lval_expr, _, rval_expr) -> (
                record_object_property_assignment_mapping lval_expr rval_expr;
                (match lval_expr.G.e with
                | G.N alias_name ->
                    record_object_property_mappings alias_name rval_expr;
                    record_object_property_alias_mapping alias_name rval_expr;
                    record_function_alias_mapping alias_name rval_expr
                | _ -> ());
                let var_name =
                  match lval_expr.G.e with
                  | G.N name -> Some name
                  | G.DotAccess
                      ( { e = G.IdSpecial ((G.This | G.Self), _); _ },
                        _,
                        G.FN (G.Id _ as name) ) ->
                      Some name
                  | G.DotAccess (obj_expr, _, G.FN _) when lang = Lang.Go -> (
                      match obj_expr.G.e with
                      | G.N obj_name -> (
                          let existing_mapping =
                            List.find_opt
                              (fun (var, _) ->
                                match (var, obj_name) with
                                | G.Id ((str1, _), _), G.Id ((str2, _), _) ->
                                    str1 = str2
                                | _ -> false)
                              !object_mappings
                          in
                          match existing_mapping with
                          | Some (_, _) -> None
                          | None -> Some obj_name)
                      | _ -> None)
                  | _ -> None
                in
                let class_name =
                  class_name_from_expr rval_expr
                in
                match (var_name, class_name) with
                | Some var, Some cls ->
                    object_mappings := (var, cls) :: !object_mappings
                | _ -> ())
            | G.AssignOp (lval_expr, _, rval_expr) -> (
                let var_name =
                  match lval_expr.G.e with
                  | G.N name -> Some name
                  | _ -> None
                in
                let class_name =
                  extract_class_name_from_constructor rval_expr lang class_names
                in
                match (var_name, class_name) with
                | Some var, Some cls ->
                    object_mappings := (var, cls) :: !object_mappings
                | _ -> ())
            | _ -> ())
        | _ -> ());
        super#visit_stmt () stmt

      method! visit_definition () def =
        (match def with
        | entity, G.ClassDef class_def -> (
            match entity.G.name with
            | G.EN class_name ->
                record_class_constructor_param_field_mappings class_name
                  class_def
            | _ -> ())
        | entity, G.VarDef var_def -> (
            match (entity.G.name, var_def.G.vinit) with
            | G.EN var_name, Some init_expr -> (
                record_object_property_mappings var_name init_expr;
                record_object_property_alias_mapping var_name init_expr;
                record_destructured_object_property_mappings init_expr;
                record_function_alias_mapping var_name init_expr;
                let class_name = class_name_from_expr init_expr in
                match class_name with
                | Some cls ->
                    object_mappings := (var_name, cls) :: !object_mappings
                | _ -> ())
            | _ -> ())
        | _, G.FuncDef fdef ->
            Tok.unbracket fdef.G.fparams
            |> List.iter (function
                 | G.Param
                     {
                       G.pname = Some ((param_name, param_tok));
                       ptype = Some param_type;
                       pattrs;
                       pinfo;
                       _;
                     }
                   when List.exists is_parameter_property_attr pattrs -> (
                     match class_name_from_type param_type with
                     | Some cls ->
                         let field_name =
                           G.Id ((param_name, param_tok), pinfo)
                         in
                         object_mappings := (field_name, cls) :: !object_mappings
                     | None -> ())
                 | _ -> ())
        | _ -> ());
        super#visit_definition () def
    end
  in

  function_return_visitor#visit_program () ast;
  visitor#visit_program () ast;
  !object_mappings

(*****************************************************************************)
(* Constructor Detection Utilities *)
(*****************************************************************************)

(* Check if a function is a constructor for the given language *)
let is_constructor (lang : Lang.t) (func_name : string)
    (class_name_opt : string option) : bool =
  let config = Lang_config.get lang in
  List.mem func_name config.constructor_names
  ||
  match class_name_opt with
  | Some class_name ->
      func_name = class_name
  | None -> false

(* Get all constructor method names for a language *)
let get_constructor_names (lang : Lang.t) : string list =
  (Lang_config.get lang).constructor_names

(* Check if language uses 'new' keyword *)
let uses_new_keyword (lang : Lang.t) : bool =
  (Lang_config.get lang).uses_new_keyword

(*****************************************************************************)
(* Unified Constructor Execution *)
(*****************************************************************************)

let execute_unified_constructor constructor_exp args args_taints
    check_function_call_fn env =
  match check_function_call_fn env constructor_exp args args_taints with
  | Some (call_taints, shape, updated_lval_env) ->
      Some (call_taints, shape, updated_lval_env)
  | None -> None

let execute_constructor_call lang constructor_name class_name args =
  if is_constructor lang constructor_name class_name then
    Some (constructor_name, class_name, args)
  else None

(*****************************************************************************)
(* C++ Constructor Statement Detection *)
(*****************************************************************************)

let detect_cpp_constructor_defstmt stmt class_names =
  match stmt.G.s with
  | G.DefStmt (ent, G.VarDef { G.vinit = None; vtype = Some ty; vtok = _ }) -> (
      match (ent.name, ty.G.t) with
      | G.EN (G.Id ((var_name, _), _)), G.TyFun (params, return_type) -> (
          match return_type.G.t with
          | G.TyN (G.Id ((class_name, _), _) as name)
            when is_known_class name class_names ->
              Some (var_name, class_name, params)
          | _ -> None)
      | _ -> None)
  | _ -> None

(*****************************************************************************)
(* Debugging and Display *)
(*****************************************************************************)

let show_object_mapping (var_name, class_name) =
  let var_str =
    match var_name with
    | G.Id ((str, _), _) -> str
    | _ -> "???"
  in
  let class_str =
    match class_name with
    | G.Id ((str, _), _) -> str
    | _ -> "???"
  in
  Printf.sprintf "%s -> %s" var_str class_str

let show_object_mappings (mappings : object_mapping list) =
  mappings
  |> List.map show_object_mapping
  |> String.concat "; " |> Printf.sprintf "[%s]"
