let evidence_value operation value =
  Abstract_value.string_constant value ~trust:Abstract_value.Trusted
    ~secrecy:Abstract_value.Public
    ~provenance:
      [ { origin = "workflow-verifier.lock"; span = Span.none; operation } ]

let dependency_reference_matches (node : Ir.node) reference =
  node.name = reference
  || node.name = "docker:" ^ reference
  ||
  match List.assoc_opt "dependency.reference" node.attributes with
  | None -> false
  | Some value -> (
      match Abstract_value.constants value with
      | Some values -> List.mem reference values
      | None -> false)

let apply lock (compilation : Frontend_intf.compilation) =
  let resolved =
    compilation.dependencies
    |> List.filter_map (fun (dependency : Frontend_intf.dependency) ->
        Option.map
          (fun entry -> (dependency, entry))
          (Lockfile.find lock dependency.provider dependency.reference))
  in
  let dependencies =
    compilation.dependencies
    |> List.map (fun (dependency : Frontend_intf.dependency) ->
        match Lockfile.find lock dependency.provider dependency.reference with
        | None -> dependency
        | Some entry ->
            {
              dependency with
              status =
                Frontend_intf.Locked
                  { revision = entry.revision; digest = entry.digest };
            })
  and nodes =
    compilation.graph.nodes
    |> List.map (fun (node : Ir.node) ->
        if node.kind <> Ir.Call then node
        else
          match
            List.find_opt
              (fun (dependency, _) ->
                dependency_reference_matches node
                  dependency.Frontend_intf.reference)
              resolved
          with
          | None -> node
          | Some (_, entry) ->
              let capabilities, effects, unknown, summary_attributes =
                match entry.Lockfile.summary with
                | None ->
                    ( node.capabilities,
                      node.effects,
                      Some
                        (Unknown.Missing_evidence
                           ("lock entry has no semantic summary for "
                          ^ entry.reference)),
                      [] )
                | Some summary ->
                    ( Util.deduplicate_compare Stdlib.compare
                        (node.capabilities @ summary.capabilities),
                      Util.deduplicate_compare Stdlib.compare
                        (node.effects @ summary.effects),
                      (if summary.complete then None
                       else
                         Some
                           (Unknown.Missing_evidence
                              (String.concat "; " summary.reasons))),
                      [
                        ( "dependency.summary",
                          evidence_value "lock semantic summary"
                            (if summary.complete then "complete"
                             else "incomplete") );
                      ] )
              in
              {
                node with
                capabilities;
                effects;
                attributes =
                  [
                    ( "dependency.digest",
                      evidence_value "lock digest" entry.Lockfile.digest );
                    ( "dependency.revision",
                      evidence_value "lock revision" entry.revision );
                    ( "dependency.source",
                      evidence_value "lock source" entry.source );
                  ]
                  @ summary_attributes
                  @ List.remove_assoc "dependency.digest"
                      (List.remove_assoc "dependency.revision"
                         (List.remove_assoc "dependency.source"
                            (List.remove_assoc "dependency.summary"
                               node.attributes)));
                unknown;
              })
  in
  {
    compilation with
    dependencies;
    graph = Ir.finalize { compilation.graph with nodes };
  }
