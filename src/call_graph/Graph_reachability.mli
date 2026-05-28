val compute_relevant_subgraph :
  Call_graph.G.t ->
  sources:Function_id.t list ->
  sinks:Function_id.t list ->
  Call_graph.G.t

val forward_reachable_subgraph :
  Call_graph.G.t -> Function_id.t list -> Call_graph.G.t
