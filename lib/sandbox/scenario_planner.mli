type t = {
  steps : Sandbox_protocol.step list;
  selected_jobs : string list;
  incomplete_reasons : string list;
}

val plan :
  scenario:Scenario.t -> image:string -> graphs:Ir.t list -> (t, string) result
