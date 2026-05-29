(** AST modifications/normalizations applied before IL conversion.

    These transformations normalize language-specific AST patterns into
    more canonical forms that are easier to analyze in IL/taint analysis.
*)

open Common
module G = AST_generic
module H = AST_generic_helpers

(* ========================================================================== *)
(* Lua: Array-like tables *)
(* ========================================================================== *)

(** Lua: Check if a Dict container is actually an array-like table.
    Lua tables like {1, 2, 3} are parsed as Dict with NextArrayIndex keys,
    but should be treated as arrays for taint analysis. *)
let is_lua_array_table (lang : Lang.t) (entries : G.expr list) : bool =
  lang =*= Lang.Lua
  && List.for_all
       (fun entry ->
         match entry.G.e with
         | G.Assign ({ e = G.IdSpecial (G.NextArrayIndex, _); _ }, _, _) -> true
         | _ -> false)
       entries

(** Lua: Extract values from array-like table entries.
    Converts Assign(NextArrayIndex, value) entries to just the values. *)
let extract_lua_array_values (entries : G.expr list) : G.expr list =
  entries
  |> List.map (fun entry ->
         match entry.G.e with
         | G.Assign (_, _, value) -> value
         | _ -> assert false)

(* ========================================================================== *)
(* Elixir: ShortLambda / Capture operator *)
(* ========================================================================== *)

(** Elixir: Convert ShortLambda to a regular Lambda.

    ShortLambda comes from Elixir_to_generic as:
    OtherExpr("ShortLambda", [Params params; S body_stmt])

    This converts it to a proper Lambda for IL/taint analysis. *)
let convert_elixir_short_lambda (e : G.expr) : G.expr =
  match e.G.e with
  | G.OtherExpr (("ShortLambda", tok), [ G.Params params; G.S body ]) ->
      let fdef =
        {
          G.fparams = Tok.unsafe_fake_bracket params;
          frettype = None;
          fkind = (G.LambdaKind, tok);
          fbody = G.FBStmt body;
        }
      in
      G.Lambda fdef |> G.e
  | _ -> e

(* ========================================================================== *)
(* Scheme: define function forms *)
(* ========================================================================== *)

let tok_of_expr_or_fake (expr : G.expr) : Tok.t =
  match H.ii_of_any (G.E expr) with
  | tok :: _ -> tok
  | [] -> G.fake "expr"

let params_of_scheme_define_args (args : G.argument list) : G.parameter list option
    =
  let params =
    args
    |> List.filter_map (function
         | G.Arg { e = G.N (G.Id (id, id_info)); _ } ->
             Some
               (G.Param
                  {
                    pname = Some id;
                    pdefault = None;
                    ptype = None;
                    pattrs = [];
                    pinfo = id_info;
                  })
         | _ -> None)
  in
  if Int.equal (List.length params) (List.length args) then Some params
  else None

let exprs_of_scheme_define_body (args : G.argument list) : G.expr list option =
  let exprs =
    args
    |> List.filter_map (function
         | G.Arg expr -> Some expr
         | _ -> None)
  in
  if Int.equal (List.length exprs) (List.length args) then Some exprs else None

let scheme_function_body (body_exprs : G.expr list) : G.stmt =
  match List.rev body_exprs with
  | [] -> G.emptystmt (G.fake "()")
  | last :: rev_prefix ->
      let prefix = List.rev rev_prefix |> List_.map G.exprstmt in
      let return_stmt =
        G.Return (tok_of_expr_or_fake last, Some last, G.sc) |> G.s
      in
      G.Block (G.fake "(", prefix @ [ return_stmt ], G.fake ")") |> G.s

let scheme_define_function_stmt (stmt : G.stmt) : G.stmt =
  match stmt.G.s with
  | G.ExprStmt
      ( {
          e =
            G.Call
              ( { e = G.N (G.Id (("define", _), _)); _ },
                ( _,
                  G.Arg
                    {
                      e =
                        G.Call
                          ( { e = G.N (G.Id (fn_id, fn_id_info)); _ },
                            (_, param_args, _) );
                      _;
                    }
                  :: body_args,
                  _ ) );
          _;
        },
        _ ) -> (
      match
        ( params_of_scheme_define_args param_args,
          exprs_of_scheme_define_body body_args )
      with
      | Some params, Some body_exprs ->
          let ent =
            {
              G.name = G.EN (G.Id (fn_id, fn_id_info));
              attrs = [];
              tparams = None;
            }
          in
          let fdef =
            {
              G.fparams = Tok.unsafe_fake_bracket params;
              frettype = None;
              fkind = (G.Function, snd fn_id);
              fbody = G.FBStmt (scheme_function_body body_exprs);
            }
          in
          G.DefStmt (ent, G.FuncDef fdef) |> G.s
      | _ -> stmt)
  | _ -> stmt

let normalize_scheme_defines (ast : G.program) : G.program =
  List_.map scheme_define_function_stmt ast

(* ========================================================================== *)
(* Statement-expression function bodies *)
(* ========================================================================== *)

let unwrap_stmt_expr_block_function_body (stmt : G.stmt) : G.stmt =
  match stmt.G.s with
  | G.DefStmt
      ( ent,
        G.FuncDef
          ( {
              G.fbody =
                G.FBStmt
                  {
                    s =
                      G.ExprStmt
                        ({ e = G.StmtExpr ({ s = G.Block _; _ } as body); _ }, _);
                    _;
                  };
              _;
            } as fdef ) ) ->
      G.DefStmt (ent, G.FuncDef { fdef with G.fbody = G.FBStmt body }) |> G.s
  | _ -> stmt

let normalize_stmt_expr_block_function_bodies (ast : G.program) : G.program =
  List_.map unwrap_stmt_expr_block_function_body ast
