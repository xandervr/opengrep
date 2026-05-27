open IL
module Shape = Shape_and_sig.Shape
module Effect = Shape_and_sig.Effect
module Effects = Shape_and_sig.Effects
module G = AST_generic
module Signature = Shape_and_sig.Signature
module TRI = Taint_rule_inst
module Log = Log_tainting.Log

(*TODO: this needs better testing. The way the procedure works is as follows:
1. assume all params of a functions are tainted AND all globals are tainted (for tracking purposes).
2. run fixed point and find the possible effects.
3. for the ToSink effects: use extract_param_labels_from_sink to pick which params would flow
   into the sink if they were tainted, add those to preconditions, and combine with existing preconditions.
4. for the ToReturn effects: filter to only keep effects with real source taint (not artificial assumptions).
   NOTE: ToReturn effects don't support preconditions in the type system.
5. for the ToLval effects: filter to only keep effects with real source taint (not artificial assumptions).
   This prevents false positives from artificial global taint assumptions.
6. add all filtered/processed effects to the signature.

NOTE: The filtering of ToReturn and ToLval is important to distinguish between:
- Real taint flows (from sources like source1("taint"))
- Artificial flows (from our parameter/global assumptions used for analysis tracking) *)

type extraction_result = {
  signature : Signature.t;
  mapping : Taint_lval_env.t Dataflow_core.mapping;
}

(* Use signature database from Shape_and_sig to avoid circular dependencies *)
type signature_database = Shape_and_sig.signature_database

module FunctionMap = Shape_and_sig.FunctionMap

let extract_param_labels_from_sink (sink_info : Effect.taints_to_sink) :
    string list =
  let taints_items, _existing_precondition =
    sink_info.taints_with_precondition
  in
  taints_items
  |> List.map (fun (item : Effect.taint_to_sink_item) -> item.taint)
  |> List.fold_left
       (fun acc taint ->
         match taint.Taint.orig with
         | Taint.Var lval -> (
             match lval.base with
             | Taint.BGlob name -> fst name.ident :: acc
             | _ -> acc)
         | _ -> acc)
       []

let enclosed_vars_are_implicit_instance_fields lang =
  Lang.equal lang Lang.Java || Lang.equal lang Lang.Csharp
  || Lang.equal lang Lang.Kotlin

let implicit_this_property (expr : G.expr) id id_info : G.expr =
  let tok = snd id in
  let this_expr = { expr with G.e = G.IdSpecial (G.This, tok) } in
  { expr with G.e = G.DotAccess (this_expr, tok, G.FN (G.Id (id, id_info))) }

(* Extract this.x/self.x properties and implicit this fields from a method. *)
let extract_method_properties ~(lang : Lang.t) (fdef : G.function_definition) :
    G.expr list =
  let found_properties = ref [] in
  let visitor =
    object
      inherit [_] G.iter as super

      method! visit_expr () expr =
        (match expr.G.e with
        | G.N (G.Id (id, id_info))
          when enclosed_vars_are_implicit_instance_fields lang -> (
            match !(id_info.G.id_resolved) with
            | Some (G.EnclosedVar, _) ->
                found_properties :=
                  implicit_this_property expr id id_info :: !found_properties
            | _ -> ())
        | G.DotAccess (obj, _, G.FN (G.Id (_, _))) -> (
            (* Check if base object is IdSpecial This or Self *)
            match obj.G.e with
            | G.IdSpecial (G.This, _)
            | G.IdSpecial (G.Self, _) ->
                found_properties := expr :: !found_properties
            | G.DeRef (_, inner_obj) -> (
                match inner_obj.G.e with
                | G.IdSpecial (G.This, _) ->
                    found_properties := expr :: !found_properties
                | _ -> ())
            | _ -> ())
        | _ -> ());
        super#visit_expr () expr
    end
  in
  (* Convert function body to statement and visit it *)
  let body_stmt = AST_generic_helpers.funcbody_to_stmt fdef.fbody in
  visitor#visit_stmt () body_stmt;
  (* Sort and remove duplicates *)
  !found_properties
  |> List.sort_uniq (fun e1 e2 -> String.compare (G.show_expr e1) (G.show_expr e2))

(* Object initialization detection for different languages *)
let detect_object_initialization =
  Object_initialization.detect_object_initialization

(* Convert AST method properties to taint assumptions using AST_to_IL *)
let mk_method_property_assumptions (properties : G.expr list)
    (lang : Lang.t) : Taint_lval_env.t =
  properties
  |> List.fold_left
       (fun taint_env prop_expr ->
         (* Use AST_to_IL to convert the expression to an IL lval *)
         let il_lval = AST_to_IL.lval lang prop_expr in
         (* Convert to Taint lval - these are this.x/self.y so use BThis base *)
         let taint_lval =
           match il_lval.base with
           | VarSpecial (This, _)
           | VarSpecial (Self, _) ->
               let taint_offsets =
                 Taint.offset_of_rev_IL_offset ~rev_offset:il_lval.rev_offset
               in
               Taint.{ base = BThis; offset = taint_offsets }
           | _ ->
               (* Fallback for other cases *)
               let taint_offsets =
                 Taint.offset_of_rev_IL_offset ~rev_offset:il_lval.rev_offset
               in
               Taint.{ base = BThis; offset = taint_offsets }
         in
         let generic_taint = Taint.{ orig = Var taint_lval; tokens = [] } in
         let taint_set = Taint.Taint_set.singleton generic_taint in
         Taint_lval_env.add_lval il_lval taint_set taint_env)
       Taint_lval_env.empty

(** Helper to add a parameter with Arg shape to the environment *)
let add_param_to_env il_lval taint_set taint_arg env =
  let param_shape = Shape.Arg taint_arg in
  Taint_lval_env.add_lval_shape il_lval taint_set param_shape env

let mk_param_assumptions ?taint_inst (params : IL.param list) : Taint_lval_env.t =
  let _, env =
    params
    |> List.fold_left
         (fun (i, env) param ->
           match param with
           | IL.Param { pname; _ }
           (* NOTE: from the perspective of the function definition, a "rest" param is just *)
           (* a param. The difference is only at the call site when instantiating the args. *)
           | IL.ParamRest { pname; _ } ->
               let il_lval : IL.lval = { base = Var pname; rev_offset = [] } in
               let taint_arg : Taint.arg =
                 { name = fst pname.ident; index = i }
               in
               let taint_lval : Taint.lval =
                 { base = BArg taint_arg; offset = [] }
                 (* Use BArg instead of BGlob for function parameters *)
               in
               let generic_taint =
                 Taint.{ orig = Var taint_lval; tokens = [] }
               in
               (* Check if this parameter matches a source pattern *)
               let source_taints =
                 match taint_inst with
                 | Some tinst ->
                     let _, tok = pname.ident in
                     let any = G.Tk tok in
                     let source_pms = tinst.TRI.preds.is_source any in
                     if source_pms <> [] then
                       (* Create Src taints for matching sources using taints_of_pms *)
                       let pms_with_specs =
                         source_pms
                         |> List.map (fun (tm : Rule.taint_source Taint_spec_match.t) ->
                                (tm.Taint_spec_match.spec_pm, tm.spec))
                       in
                       Taint.taints_of_pms ~incoming:Taint.Taint_set.empty pms_with_specs
                     else
                       Taint.Taint_set.empty
                 | None -> Taint.Taint_set.empty
               in
               let taint_set = Taint.Taint_set.union (Taint.Taint_set.singleton generic_taint) source_taints in
               (* Give the parameter an Arg shape so it can be used in HOF *)
               let new_env = add_param_to_env il_lval taint_set taint_arg env in
               (i + 1, new_env)
           | IL.ParamPattern pat -> (
               (* Extract parameter name from pattern for Rust function parameters *)
               match pat with
               | G.PatId (name, id_info) ->
                   let il_name = AST_to_IL.var_of_id_info name id_info in
                   let il_lval : IL.lval =
                     { base = Var il_name; rev_offset = [] }
                   in
                   let taint_arg : Taint.arg = { name = fst name; index = i } in
                   let taint_lval : Taint.lval =
                     { base = BArg taint_arg; offset = [] }
                     (* Use BArg for function parameters *)
                   in
                   let generic_taint =
                     Taint.{ orig = Var taint_lval; tokens = [] }
                   in
                   let taint_set = Taint.Taint_set.singleton generic_taint in
                   let new_env = add_param_to_env il_lval taint_set taint_arg env in
                   (i + 1, new_env)
               | G.PatTyped (G.PatId (name, id_info), _) ->
                   (* Handle typed patterns like PatTyped(PatId(...), type) for Rust *)
                   let il_name = AST_to_IL.var_of_id_info name id_info in
                   let il_lval : IL.lval =
                     { base = Var il_name; rev_offset = [] }
                   in
                   let taint_arg : Taint.arg = { name = fst name; index = i } in
                   let taint_lval : Taint.lval =
                     { base = BArg taint_arg; offset = [] }
                     (* Use BArg for function parameters *)
                   in
                   let generic_taint =
                     Taint.{ orig = Var taint_lval; tokens = [] }
                   in
                   let taint_set = Taint.Taint_set.singleton generic_taint in
                   let new_env = add_param_to_env il_lval taint_set taint_arg env in
                   (i + 1, new_env)
               | _ ->
                   (* Fallback for other pattern types *)
                   (i + 1, env))
           | IL.ParamFixme -> (i + 1, env))
         (0, Taint_lval_env.empty)
  in
  env

let max_bash_arg_index_in_taint acc (taint : Taint.taint) =
  match taint.Taint.orig with
  | Taint.Var { base = Taint.BArg { index; _ }; _ } when index >= 0 -> (
      match acc with
      | None -> Some index
      | Some prev -> Some (max prev index))
  | _ -> acc

let max_bash_arg_index_in_taints acc taints =
  Taint.Taint_set.fold
    (fun taint acc -> max_bash_arg_index_in_taint acc taint)
    taints acc

let max_bash_arg_index_in_shape acc = function
  | Shape.Arg { index; _ } when index >= 0 -> (
      match acc with
      | None -> Some index
      | Some prev -> Some (max prev index))
  | _ -> acc

let max_bash_arg_index_in_effect acc = function
  | Effect.ToReturn return_info ->
      let acc =
        max_bash_arg_index_in_taints acc return_info.data_taints
      in
      max_bash_arg_index_in_shape acc return_info.data_shape
  | Effect.ToSink sink_info ->
      let taints_items, _ = sink_info.taints_with_precondition in
      taints_items
      |> List.fold_left
           (fun acc (item : Effect.taint_to_sink_item) ->
             max_bash_arg_index_in_taint acc item.taint)
           acc
  | Effect.ToLval (taints, lval) ->
      let acc = max_bash_arg_index_in_taints acc taints in
      (match lval.Taint.base with
      | Taint.BArg { index; _ } when index >= 0 -> (
          match acc with
          | None -> Some index
          | Some prev -> Some (max prev index))
      | _ -> acc)
  | Effect.CleanLval lval -> (
      match lval.Taint.base with
      | Taint.BArg { index; _ } when index >= 0 -> (
          match acc with
          | None -> Some index
          | Some prev -> Some (max prev index))
      | _ -> acc)
  | Effect.ToSinkInCall { args_taints; _ } ->
      args_taints
      |> List.fold_left
           (fun acc arg ->
             match arg with
             | IL.Unnamed (taints, shape)
             | IL.Named (_, (taints, shape)) ->
                 let acc = max_bash_arg_index_in_taints acc taints in
                 max_bash_arg_index_in_shape acc shape)
           acc

let add_bash_implicit_params_from_effects lang params effects =
  if not (Lang.equal lang Lang.Bash) then params
  else
    let max_index =
      Effects.fold
        (fun eff acc -> max_bash_arg_index_in_effect acc eff)
        effects None
    in
    match max_index with
    | None -> params
    | Some max_index ->
        let needed = max_index + 1 in
        if List.length params >= needed then params
        else
          let existing = List.length params in
          params
          @ List.init (needed - existing) (fun i ->
                let n = existing + i + 1 in
                Signature.P ("$" ^ string_of_int n))

let extract_signature (taint_inst : TRI.t) ?(in_env : Taint_lval_env.t option)
    ?(name : IL.name option) ?(signature_db : signature_database option)
    ?(builtin_signature_db : Shape_and_sig.builtin_signature_database option)
    ?(call_graph : Call_graph.G.t option = None)
    (func_cfg : IL.fun_cfg) : extraction_result =
  let params = Signature.of_IL_params func_cfg.params in
  let param_assumptions = mk_param_assumptions ~taint_inst func_cfg.params in
  let normalize_file file = Fpath.to_string (Fpath.normalize file) in
  let function_file =
    match name with
    | None -> None
    | Some name ->
        let file, _line, _col =
          Function_id.to_file_line_col (Function_id.of_il_name name)
        in
        if String.equal file "unknown" then None else Some file
  in
  let sink_is_in_function_file (sink_info : Effect.taints_to_sink) =
    match function_file with
    | None -> true
    | Some function_file ->
        let start_loc, _end_loc =
          sink_info.sink.pm.Core_match.range_loc
        in
        String.equal function_file (normalize_file start_loc.pos.file)
  in
  let combined_env =
    match in_env with
    | Some env -> Taint_lval_env.union env param_assumptions
    | None -> param_assumptions
  in
  let fixpoint_effects, mapping =
    Dataflow_tainting.fixpoint taint_inst ~in_env:combined_env ?name
      ?signature_db ?builtin_signature_db ?call_graph func_cfg
  in
  let effects_with_preconditions =
    fixpoint_effects |> Effects.elements
    |> List.fold_left
         (fun acc eff ->
           match eff with
           | Effect.ToSink sink_info ->
               if not (sink_is_in_function_file sink_info) then acc
               else
                 let param_labels = extract_param_labels_from_sink sink_info in
                 if param_labels <> [] then
                   let filtered_labels =
                     List.filter (fun label -> label <> "__SOURCE__") param_labels
                   in
                   let unique_labels =
                     List.sort_uniq String.compare filtered_labels
                   in
                   let param_precondition =
                     match unique_labels with
                     | [] -> Rule.PBool true
                     | [ label ] -> Rule.PVariable label
                     | labels ->
                         Rule.POr (List.map (fun l -> Rule.PVariable l) labels)
                   in
                   let taints_items, existing_precondition =
                     sink_info.taints_with_precondition
                   in
                   (* Note there might be existing preconditions and we do not lose them. *)
                   let combined_precondition =
                     match (existing_precondition, param_precondition) with
                     | Rule.PBool true, p -> p
                     | Rule.PLabel "__SOURCE__", p -> p
                     | e, Rule.PBool true -> e
                     | e, p -> Rule.PAnd [ e; p ]
                   in
                   let updated_sink_info =
                     {
                       sink_info with
                       taints_with_precondition =
                         (taints_items, combined_precondition);
                     }
                   in
                   Effects.add (Effect.ToSink updated_sink_info) acc
                 else Effects.add eff acc
          | Effect.ToReturn return_info ->
              (* Retain return effects that carry any meaningful taint information.
               *
               * Historically we dropped summaries that only referenced parameters to
               * avoid storing "artificial" taint. That prevented --taint-intrafile
               * from propagating taint through helper functions like `return x;`.
               * We now keep parameter/global/control taints so callers can
               * materialize them, while still discarding purely shape-only summaries. *)
              let func_name = Option.fold ~none:"<anonymous>" ~some:IL.str_of_name name in
              Log.debug (fun m ->
                  m "TAINT_SIG: ToReturn effect captured for %s" func_name);
              let filtered_data_taints =
                return_info.data_taints
                |> Taint.Taint_set.filter (fun taint ->
                       match taint.Taint.orig with
                       | Taint.Shape_var _ -> false (* Shape vars cannot materialize values. *)
                       | _ -> true)
              in
              (* Use taints_and_shape_are_relevant to check if either top-level taints
               * OR nested shape taints exist (field-sensitive taint tracking) *)
              let has_data_or_shape =
                Taint_shape.taints_and_shape_are_relevant filtered_data_taints return_info.data_shape
              in
              let has_control =
                not (Taint.Taint_set.is_empty return_info.control_taints)
              in
              if has_data_or_shape || has_control then
                let filtered_return_info =
                  { return_info with data_taints = filtered_data_taints }
                in
                Effects.add (Effect.ToReturn filtered_return_info) acc
              else acc
           | Effect.ToLval (taints, _lval) ->
               (* Keep ToLval effects - they represent legitimate data flow patterns
                * that become important when parameters receive real source taint *)
               let has_relevant_taint =
                 taints |> Taint.Taint_set.elements
                 |> List.exists (fun taint ->
                        match taint.Taint.orig with
                        | Taint.Src _ -> true (* Real source taint *)
                        | Taint.Var _ -> true (* Parameter taint - keep it! *)
                        | Taint.Shape_var _ -> false
                        | Taint.Control -> true (* Real control taint *))
               in
               if has_relevant_taint then Effects.add eff acc
             else acc (* Skip only effects with no relevant taint *)
           | Effect.CleanLval _ -> Effects.add eff acc
           | Effect.ToSinkInCall _ -> Effects.add eff acc)
         Effects.empty
  in
  let params =
    add_bash_implicit_params_from_effects taint_inst.lang params
      effects_with_preconditions
  in
  let signature = { Signature.params; effects = effects_with_preconditions } in
  { signature; mapping }

let mk_global_assumptions_with_sids
    (global_vars : (string * G.SId.t) list) : Taint_lval_env.t =
  global_vars
  |> List.fold_left
       (fun env (var_name, sid) ->
         let fake_tok = Tok.unsafe_fake_tok var_name in
         let var_id =
           IL.
             {
               ident = (var_name, fake_tok);
               sid;
               id_info = G.empty_id_info ();
             }
         in
         let il_lval : IL.lval = { base = Var var_id; rev_offset = [] } in
         let taint_lval : Taint.lval = { base = BGlob var_id; offset = [] } in
         let generic_taint = Taint.{ orig = Var taint_lval; tokens = [] } in
         let taint_set = Taint.Taint_set.singleton generic_taint in
         Taint_lval_env.add_lval il_lval taint_set env)
       Taint_lval_env.empty

let mk_global_tracking_without_taint
    (global_vars : (string * G.SId.t) list) : Taint_lval_env.t =
  global_vars
  |> List.fold_left
       (fun env (var_name, sid) ->
         let fake_tok = Tok.unsafe_fake_tok var_name in
         let var_id =
           IL.
             {
               ident = (var_name, fake_tok);
               sid;
               id_info = G.empty_id_info ();
             }
         in
         let il_lval : IL.lval = { base = Var var_id; rev_offset = [] } in
         (* Register the lval for tracking but with empty taint set *)
         Taint_lval_env.add_lval il_lval Taint.Taint_set.empty env)
       Taint_lval_env.empty

let extract_global_var_sids_from_ast (ast : G.program) :
    (string * G.SId.t) list =
  ast
  |> List.fold_left
       (fun acc stmt ->
         match stmt with
         | {
          G.s =
            G.ExprStmt ({ e = G.Assign (lhs, _, _); _ }, _);
          _;
         } -> (
             match lhs with
             | { e = G.N (G.Id ((name, _), id_info)); _ }
               -> (
                 match !(id_info.id_resolved) with
                 | Some (G.Global, sid) -> (name, sid) :: acc
                 | _ -> acc)
             | _ -> acc)
         | _ -> acc)
       []
  |> List.rev

let extract_signature_with_file_context
    ~(arity : Shape_and_sig.sig_arity)
    ?(db : signature_database = Shape_and_sig.empty_signature_database ())
    ?(builtin_signature_db : Shape_and_sig.builtin_signature_database option)
    ~(name : IL.name)
    ?(method_properties : AST_generic.expr list = [])
    ?(call_graph : Call_graph.G.t option = None)
    (taint_inst : Taint_rule_inst.t)
    func_cfg
    (ast : G.program) : signature_database * Signature.t =
  let global_sids = extract_global_var_sids_from_ast ast in
  let global_env = mk_global_assumptions_with_sids global_sids in

  (* Add method property assumptions for methods with properties *)
  let combined_global_env =
    match method_properties with
    | [] -> global_env
    | props ->
        let method_property_env =
          mk_method_property_assumptions props taint_inst.lang
        in
        Taint_lval_env.union global_env method_property_env
  in

  let { signature; _ } =
    extract_signature taint_inst ~in_env:combined_global_env ~name
      ~signature_db:db ?builtin_signature_db ~call_graph func_cfg
  in
  let updated_db = Shape_and_sig.add_signature db (Function_id.of_il_name name) {sig_ = signature; arity} in
  (updated_db, signature)

let show_signature_extraction func_name signature =
  Printf.sprintf "Function %s signature: %s"
    (Option.value func_name ~default:"<anonymous>")
    (Signature.show signature)
