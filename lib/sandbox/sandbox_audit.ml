type status = Verified | Incomplete of string list

type t = {
  schema : string;
  plan_digest : string;
  source_digest : string;
  backend : string;
  controls_digest : string;
  status : status;
  observed_effects : Ir.observable_effect list;
  reconciliation : Property.t option;
  event_count : int;
  evidence_tail : string;
}

let evaluate_internal graphs ~plan ~evidence =
  let open Util in
  if evidence.Evidence.plan_digest <> plan.Sandbox_protocol.digest then
    Error "evidence is bound to a different execution plan"
  else
    let* () = Evidence.validate evidence in
    let attested =
      evidence.events
      |> List.filter_map (fun event ->
          match event.Evidence.body with
          | Control_attested value -> Some value
          | _ -> None)
      |> Util.deduplicate_strings
    in
    let controls_digest = Sandbox_protocol.controls_digest plan.controls in
    let backend_attestations =
      evidence.events
      |> List.filter_map (fun event ->
          match event.Evidence.body with
          | Backend_attested { id; version; platform; controls_digest } ->
              Some (id, version, platform, controls_digest)
          | _ -> None)
    in
    let backend_reasons =
      match backend_attestations with
      | [] -> [ "backend attestation is missing from evidence" ]
      | [ (id, version, platform, observed) ] ->
          (if id = Sandbox_protocol.backend_name plan.backend then []
           else [ "backend attestation identity does not match the plan" ])
          @ (if observed = controls_digest then []
             else
               [ "backend attestation controls digest does not match the plan" ])
          @
          if version = "" || platform = "" then
            [ "backend attestation identity is incomplete" ]
          else []
      | _ -> [ "multiple backend attestations are ambiguous" ]
    in
    let missing_controls =
      plan.controls
      |> List.filter_map (fun control ->
          let name = Sandbox_protocol.control_name control in
          if List.mem name attested then None
          else Some ("control not attested: " ^ name))
    and backend_errors =
      evidence.events
      |> List.filter_map (fun event ->
          match event.Evidence.body with
          | Backend_error message -> Some ("backend error: " ^ message)
          | Process_exited { code } when code <> 0 ->
              Some (Printf.sprintf "process exited with code %d" code)
          | _ -> None)
    and plan_reasons =
      match plan.status with
      | Complete -> []
      | Incomplete values -> values
    in
    let reconciliation =
      Option.map (fun graphs -> Reconcile.envelope ~graphs ~evidence) graphs
    in
    let reconciliation_reasons =
      match reconciliation with
      | Some { Property.state = Violated; explanation; _ } -> [ explanation ]
      | Some { state = Unknown _; explanation; _ } -> [ explanation ]
      | Some { state = Proved | Not_applicable; _ } | None -> []
    in
    let reasons =
      plan_reasons @ backend_reasons @ missing_controls @ backend_errors
      @ reconciliation_reasons
      |> Util.deduplicate_strings
    in
    let observed_effects = Evidence.observed_effects evidence
    and evidence_tail =
      match List.rev evidence.events with
      | event :: _ -> event.digest
      | [] -> evidence.plan_digest
    in
    Ok
      {
        schema = "sandbox-audit-v1";
        plan_digest = plan.digest;
        source_digest = plan.source_digest;
        backend = Sandbox_protocol.backend_name plan.backend;
        controls_digest;
        status = (if reasons = [] then Verified else Incomplete reasons);
        observed_effects;
        reconciliation;
        event_count = List.length evidence.events;
        evidence_tail;
      }

let evaluate ~plan ~evidence = evaluate_internal None ~plan ~evidence

let evaluate_with_graphs ~graphs ~plan ~evidence =
  evaluate_internal (Some graphs) ~plan ~evidence

let status_json = function
  | Verified -> Json.Object [ ("state", Json.String "verified") ]
  | Incomplete reasons ->
      Json.Object
        [
          ( "reasons",
            Json.Array (List.map (fun value -> Json.String value) reasons) );
          ("state", Json.String "incomplete");
        ]

let to_json audit =
  Json.Object
    [
      ("backend", Json.String audit.backend);
      ("controls_digest", Json.String audit.controls_digest);
      ("event_count", Json.Int audit.event_count);
      ("evidence_tail", Json.String audit.evidence_tail);
      ( "observed_effects",
        Json.Array
          (List.map
             (fun observable -> Json.String (Ir.effect_name observable))
             audit.observed_effects) );
      ("plan_digest", Json.String audit.plan_digest);
      ( "reconciliation",
        Option.fold ~none:Json.Null ~some:Property.to_json audit.reconciliation
      );
      ("schema", Json.String audit.schema);
      ("source_digest", Json.String audit.source_digest);
      ("status", status_json audit.status);
    ]

let to_canonical_json audit = Json.to_string (to_json audit) ^ "\n"
