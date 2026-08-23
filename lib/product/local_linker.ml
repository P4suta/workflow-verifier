type target = { relative_path : string; unit_ : Frontend_intf.source_unit }

type resolution = {
  caller : string;
  dependency : Frontend_intf.dependency;
  target : target;
}

type local_intent = { caller : string; dependency : Frontend_intf.dependency }
type lookup = Not_local | Missing | Found of target | Invalid of string

let normalize path = Util.normalize_slashes path

let drop_leading_dot path =
  let rec loop value =
    if Util.starts_with ~prefix:"./" value then
      loop (String.sub value 2 (String.length value - 2))
    else value
  in
  loop path

let trim_trailing_slash path =
  let rec loop value =
    if String.length value > 1 && Util.ends_with ~suffix:"/" value then
      loop (String.sub value 0 (String.length value - 1))
    else value
  in
  loop path

let relative_to_root ~root path =
  let root = normalize root |> drop_leading_dot |> trim_trailing_slash
  and path = normalize path |> drop_leading_dot in
  if root = "" || root = "." then Some path
  else if path = root then Some ""
  else
    let prefix = root ^ "/" in
    if Util.starts_with ~prefix path then
      Some
        (String.sub path (String.length prefix)
           (String.length path - String.length prefix))
    else None

let normalize_relative path =
  let rec consume stack = function
    | [] -> Some (String.concat "/" (List.rev stack))
    | "" :: rest | "." :: rest -> consume stack rest
    | ".." :: rest -> (
        match stack with
        | _ :: parent -> consume parent rest
        | [] -> None)
    | component :: rest -> consume (component :: stack) rest
  in
  consume [] (String.split_on_char '/' (normalize path))

let dirname path =
  match String.rindex_opt path '/' with
  | None -> ""
  | Some index -> String.sub path 0 index

let has_yaml_extension path =
  let path = String.lowercase_ascii path in
  Util.ends_with ~suffix:".yml" path || Util.ends_with ~suffix:".yaml" path

let without_leading_slash path =
  let rec loop value =
    if Util.starts_with ~prefix:"/" value then
      loop (String.sub value 1 (String.length value - 1))
    else value
  in
  loop path

let azure_template_reference reference =
  match String.rindex_opt reference '@' with
  | None -> Some reference
  | Some index ->
      let alias =
        String.sub reference (index + 1) (String.length reference - index - 1)
      in
      if String.lowercase_ascii alias = "self" then
        Some (String.sub reference 0 index)
      else None

let local_candidates ~caller (dependency : Frontend_intf.dependency) =
  let reference = normalize dependency.reference in
  match (dependency.provider, dependency.kind) with
  | Ir.Github, Action
    when Util.starts_with ~prefix:"./" reference
         || Util.starts_with ~prefix:"../" reference ->
      let path = drop_leading_dot reference in
      if has_yaml_extension path then Some [ path ]
      else Some [ path ^ "/action.yml"; path ^ "/action.yaml" ]
  | Gitlab, Include
    when (not (Util.contains ~needle:"://" reference))
         && (not (String.contains reference '@'))
         && (has_yaml_extension reference
            || Util.starts_with ~prefix:"/" reference
            || Util.starts_with ~prefix:"./" reference
            || Util.starts_with ~prefix:"../" reference) ->
      Some [ without_leading_slash (drop_leading_dot reference) ]
  | Azure, Template -> (
      match azure_template_reference reference with
      | None -> None
      | Some path when Util.contains ~needle:"${{" path -> None
      | Some path ->
          let path = normalize path in
          if Util.starts_with ~prefix:"/" path then
            Some [ without_leading_slash path ]
          else
            let parent = dirname caller in
            Some [ (if parent = "" then path else parent ^ "/" ^ path) ])
  | _ -> None

let source_index ~root sources =
  sources
  |> List.filter_map (fun (unit_ : Frontend_intf.source_unit) ->
      Option.bind (relative_to_root ~root unit_.path) (fun relative ->
          Option.map (fun path -> (path, unit_)) (normalize_relative relative)))
  |> List.sort (fun (left, _) (right, _) -> String.compare left right)

let find_target ~index ~caller dependency =
  match local_candidates ~caller dependency with
  | None -> Not_local
  | Some candidates -> (
      let normalized =
        candidates
        |> List.fold_left
             (fun result candidate ->
               match (result, normalize_relative candidate) with
               | (Error _ as error), _ -> error
               | Ok _, None ->
                   Error
                     ("local dependency escapes the workspace: "
                    ^ dependency.Frontend_intf.reference)
               | Ok values, Some value -> Ok (value :: values))
             (Ok [])
      in
      match normalized with
      | Error message -> Invalid message
      | Ok candidates -> (
          let matches =
            candidates
            |> List.concat_map (fun candidate ->
                List.filter_map
                  (fun (path, unit_) ->
                    if path = candidate then
                      Some { relative_path = path; unit_ }
                    else None)
                  index)
            |> List.sort_uniq (fun left right ->
                String.compare left.relative_path right.relative_path)
          in
          match matches with
          | [] -> Missing
          | [ target ] -> Found target
          | _ ->
              Invalid
                ("local dependency is ambiguous: "
               ^ dependency.Frontend_intf.reference)))

let problem (dependency : Frontend_intf.dependency) code message =
  { Frontend_intf.code; message; span = dependency.Frontend_intf.span }

let compilation_key ~root (compilation : Frontend_intf.compilation) =
  let path =
    Option.bind
      (relative_to_root ~root compilation.graph.source)
      normalize_relative
    |> Option.value ~default:(normalize compilation.graph.source)
  in
  Ir.provider_name compilation.provider ^ "\000" ^ path

let target_key provider target =
  Ir.provider_name provider ^ "\000" ^ target.relative_path

let collect ~root ~index initial =
  let rec visit seen compiled resolutions local_intents errors = function
    | [] ->
        if errors = [] then
          Ok (List.rev compiled, List.rev resolutions, List.rev local_intents)
        else Error (List.rev errors)
    | (compilation : Frontend_intf.compilation) :: pending ->
        let caller =
          Option.bind
            (relative_to_root ~root compilation.graph.source)
            normalize_relative
          |> Option.value ~default:(normalize compilation.graph.source)
        in
        let pending, resolutions, local_intents, errors, seen =
          compilation.dependencies
          |> List.fold_left
               (fun (pending, resolutions, local_intents, errors, seen)
                    dependency ->
                 match find_target ~index ~caller dependency with
                 | Not_local ->
                     (pending, resolutions, local_intents, errors, seen)
                 | Missing ->
                     ( pending,
                       resolutions,
                       { caller; dependency } :: local_intents,
                       errors,
                       seen )
                 | Invalid message ->
                     ( pending,
                       resolutions,
                       local_intents,
                       problem dependency "LOCAL-DEPENDENCY" message :: errors,
                       seen )
                 | Found target -> (
                     let resolution = { caller; dependency; target } in
                     let local_intents =
                       { caller; dependency } :: local_intents
                     in
                     let key = target_key compilation.provider target in
                     if List.mem key seen then
                       ( pending,
                         resolution :: resolutions,
                         local_intents,
                         errors,
                         seen )
                     else
                       match
                         Frontend.compile_string ~provider:compilation.provider
                           ~path:target.unit_.path ~source:target.unit_.source
                           ()
                       with
                       | Error problems ->
                           ( pending,
                             resolution :: resolutions,
                             local_intents,
                             List.rev_append problems errors,
                             key :: seen )
                       | Ok target_compilation ->
                           ( target_compilation :: pending,
                             resolution :: resolutions,
                             local_intents,
                             errors,
                             key :: seen )))
               (pending, resolutions, local_intents, errors, seen)
        in
        visit seen (compilation :: compiled) resolutions local_intents errors
          pending
  in
  let seen = List.map (compilation_key ~root) initial in
  visit seen [] [] [] [] initial

let evidence operation value =
  Abstract_value.string_constant value ~trust:Abstract_value.Trusted
    ~secrecy:Abstract_value.Public
    ~provenance:[ { origin = "workspace source"; span = Span.none; operation } ]

let replace_attribute name value attributes =
  (name, value) :: List.remove_assoc name attributes

let matching_resolution caller (resolutions : resolution list)
    (dependency : Frontend_intf.dependency) =
  List.find_opt
    (fun (resolution : resolution) ->
      resolution.caller = caller
      && resolution.dependency.provider = dependency.provider
      && resolution.dependency.kind = dependency.kind
      && resolution.dependency.reference = dependency.reference)
    resolutions

let matching_local_intent caller (local_intents : local_intent list)
    (dependency : Frontend_intf.dependency) =
  List.exists
    (fun (intent : local_intent) ->
      intent.caller = caller
      && intent.dependency.provider = dependency.provider
      && intent.dependency.kind = dependency.kind
      && intent.dependency.reference = dependency.reference)
    local_intents

let call_matches reference (node : Ir.node) =
  node.name = reference || node.name = "child:" ^ reference

let apply_resolution ~root resolutions local_intents
    (compilation : Frontend_intf.compilation) =
  let caller =
    Option.bind
      (relative_to_root ~root compilation.graph.source)
      normalize_relative
    |> Option.value ~default:(normalize compilation.graph.source)
  in
  let resolved =
    compilation.dependencies
    |> List.filter_map (fun dependency ->
        Option.map
          (fun resolution -> (dependency, resolution))
          (matching_resolution caller resolutions dependency))
  in
  let dependencies =
    compilation.dependencies
    |> List.map (fun dependency ->
        match matching_resolution caller resolutions dependency with
        | None ->
            if matching_local_intent caller local_intents dependency then
              { dependency with mutability = Frontend_intf.Local }
            else dependency
        | Some resolution ->
            {
              dependency with
              mutability = Frontend_intf.Local;
              status =
                Locked
                  {
                    revision = "local:" ^ resolution.target.relative_path;
                    digest =
                      "sha256:"
                      ^ Sha256.digest_string resolution.target.unit_.source;
                  };
            })
  and nodes =
    compilation.graph.nodes
    |> List.map (fun (node : Ir.node) ->
        if node.kind <> Ir.Call then node
        else
          match
            List.find_opt
              (fun ((dependency : Frontend_intf.dependency), _) ->
                call_matches dependency.reference node)
              resolved
          with
          | None -> node
          | Some (_, resolution) ->
              let digest =
                "sha256:" ^ Sha256.digest_string resolution.target.unit_.source
              and revision = "local:" ^ resolution.target.relative_path in
              {
                node with
                attributes =
                  node.attributes
                  |> replace_attribute "dependency.source"
                       (evidence "local source" revision)
                  |> replace_attribute "dependency.revision"
                       (evidence "local revision" revision)
                  |> replace_attribute "dependency.digest"
                       (evidence "local digest" digest);
                unknown = None;
              })
  in
  {
    compilation with
    dependencies;
    graph = Ir.finalize { compilation.graph with nodes };
  }

let compare_compilation left right =
  match
    String.compare
      (Ir.provider_name left.Frontend_intf.provider)
      (Ir.provider_name right.Frontend_intf.provider)
  with
  | 0 -> String.compare left.graph.source right.graph.source
  | comparison -> comparison

let link ~root ~sources compilations =
  let index = source_index ~root sources in
  match collect ~root ~index compilations with
  | Error _ as error -> error
  | Ok (compilations, resolutions, local_intents) ->
      Ok
        (compilations
        |> List.map (apply_resolution ~root resolutions local_intents)
        |> List.sort compare_compilation)
