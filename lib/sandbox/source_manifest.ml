type kind = Regular | Symlink

type entry = {
  path : string;
  kind : kind;
  executable : bool;
  size : int64;
  digest : string;
  target : string option;
  identity : string option;
}

type source =
  | Regular_source of {
      contents : string;
      executable : bool;
      identity : string option;
    }
  | Symlink_source of { target : string; identity : string option }

type exclusion = { path : string; reason : string }

type budget = {
  max_file_bytes : int;
  max_entries : int;
  max_snapshot_bytes : int64;
}

type t = {
  schema : string;
  entries : entry list;
  exclusions : exclusion list;
  exclusion_policy_digest : string;
  total_size : int64;
  canonical_json : string;
  digest : string;
}

let generated_directories =
  [
    ".git";
    ".workflow-verifier";
    ".workflow-verifier-cache";
    ".workflow-verifier-output";
  ]

let default_budget =
  {
    max_file_bytes = 16 * 1024 * 1024;
    max_entries = 100_000;
    max_snapshot_bytes = 4_294_967_296L;
  }

let normalize = Util.normalize_slashes

let normalized_root root =
  let root = normalize root in
  if root <> "." && root <> "" && Util.ends_with ~suffix:"/" root then
    String.sub root 0 (String.length root - 1)
  else root

let absolute_path path =
  Filename.is_relative path |> not
  || Util.starts_with ~prefix:"/" path
  || (String.length path >= 2 && path.[1] = ':')

let safe_segments path =
  path <> ""
  && (not (absolute_path path))
  && path |> String.split_on_char '/'
     |> List.for_all (fun segment ->
         segment <> "" && segment <> "." && segment <> "..")

let relative_to ~root path =
  let root = normalized_root root and path = normalize path in
  let rec strip_current_directory value =
    if Util.starts_with ~prefix:"./" value then
      strip_current_directory (String.sub value 2 (String.length value - 2))
    else value
  in
  let relative =
    if root = "." || root = "" then strip_current_directory path
    else if path = root then ""
    else
      let prefix = root ^ "/" in
      if Util.starts_with ~prefix path then
        String.sub path (String.length prefix)
          (String.length path - String.length prefix)
      else ""
  in
  if relative = "" then
    Error
      (Printf.sprintf "source path escapes or equals manifest root: %s" path)
  else if not (Util.valid_utf8 relative) then
    Error (Printf.sprintf "source path is not valid UTF-8: %s" path)
  else if not (safe_segments relative) then
    Error (Printf.sprintf "source path is not a safe relative path: %s" path)
  else Ok relative

let path_segments path = String.split_on_char '/' (String.lowercase_ascii path)

let excluded_by prefixes path =
  let lower = String.lowercase_ascii path in
  List.find_opt
    (fun prefix ->
      let prefix = String.lowercase_ascii (normalize prefix) in
      lower = prefix || Util.starts_with ~prefix:(prefix ^ "/") lower)
    prefixes

let generated_relative path =
  path_segments path
  |> List.exists (fun segment -> List.mem segment generated_directories)

let is_generated ~root path =
  match relative_to ~root path with
  | Ok relative -> generated_relative relative
  | Error _ -> false

let is_excluded ~root ~trusted_exclusions path =
  match relative_to ~root path with
  | Ok relative ->
      generated_relative relative
      || Option.is_some (excluded_by trusted_exclusions relative)
  | Error _ -> false

let kind_name = function
  | Regular -> "regular"
  | Symlink -> "symlink"

let entry_json (entry : entry) =
  Json.Object
    [
      ("digest", Json.String entry.digest);
      ("executable", Json.Bool entry.executable);
      ("kind", Json.String (kind_name entry.kind));
      ("path", Json.String entry.path);
      ("size", Json.Int64 entry.size);
      ( "target",
        Option.fold ~none:Json.Null
          ~some:(fun value -> Json.String value)
          entry.target );
    ]

let exclusion_json (exclusion : exclusion) =
  Json.Object
    [
      ("path", Json.String exclusion.path);
      ("reason", Json.String exclusion.reason);
    ]

let body_fields manifest =
  [
    ("entries", Json.Array (List.map entry_json manifest.entries));
    ("exclusion_policy_digest", Json.String manifest.exclusion_policy_digest);
    ("exclusions", Json.Array (List.map exclusion_json manifest.exclusions));
    ( "limits",
      Json.Object
        [
          ("max_entries", Json.Int default_budget.max_entries);
          ("max_file_bytes", Json.Int default_budget.max_file_bytes);
          ("max_snapshot_bytes", Json.Int64 default_budget.max_snapshot_bytes);
        ] );
    ("schema", Json.String manifest.schema);
    ("total_size", Json.Int64 manifest.total_size);
  ]

let body_json manifest = Json.Object (body_fields manifest)

let to_json manifest =
  Json.Object (("digest", Json.String manifest.digest) :: body_fields manifest)

let to_canonical_json manifest = Json.to_string (to_json manifest) ^ "\n"

let resolve_target path target =
  let target = normalize target in
  if absolute_path target then Error "absolute symlink target is forbidden"
  else if not (Util.valid_utf8 target) then
    Error "symlink target is not valid UTF-8"
  else
    let base = Filename.dirname path |> normalize in
    let rec fold stack = function
      | [] -> Ok (String.concat "/" (List.rev stack))
      | "" :: rest | "." :: rest -> fold stack rest
      | ".." :: rest -> (
          match stack with
          | [] -> Error "symlink target escapes snapshot root"
          | _ :: stack -> fold stack rest)
      | segment :: rest -> fold (segment :: stack) rest
    in
    fold []
      (String.split_on_char '/'
         (if base = "." then target else base ^ "/" ^ target))

let validate_symlinks entries =
  let targets =
    entries
    |> List.filter_map (fun entry ->
        match (entry.kind, entry.target) with
        | Symlink, Some target -> Some (entry.path, target)
        | _ -> None)
  in
  let rec visit visiting visited path =
    if List.mem path visiting then Error ("symlink cycle at " ^ path)
    else if List.mem path visited then Ok visited
    else
      match List.assoc_opt path targets with
      | None -> Ok (path :: visited)
      | Some target -> visit (path :: visiting) (path :: visited) target
  in
  let rec loop visited = function
    | [] -> Ok ()
    | (path, _) :: rest -> (
        match visit [] visited path with
        | Error _ as error -> error
        | Ok visited -> loop visited rest)
  in
  loop [] targets

let create_from_sources ~budget ~trusted_exclusions ~root ~files =
  if
    budget.max_file_bytes < default_budget.max_file_bytes
    || budget.max_entries < default_budget.max_entries
    || budget.max_snapshot_bytes < default_budget.max_snapshot_bytes
  then Error "source-manifest-v2 budgets are below the published floor"
  else
    let exclusion_policy =
      Json.Object
        [
          ( "default",
            Json.Array
              (List.map (fun value -> Json.String value) generated_directories)
          );
          ( "trusted",
            Json.Array
              (trusted_exclusions |> Util.deduplicate_strings
              |> List.map (fun value -> Json.String (normalize value))) );
        ]
      |> Json.to_string
    in
    let exclusion_policy_digest =
      "sha256:" ^ Sha256.digest_string exclusion_policy
    in
    let rec collect paths portable identities total entries exclusions =
      function
      | [] -> (
          let entries = List.rev entries and exclusions = List.rev exclusions in
          let manifest =
            {
              schema = "source-manifest-v2";
              entries;
              exclusions;
              exclusion_policy_digest;
              total_size = total;
              canonical_json = "";
              digest = "";
            }
          in
          let unsigned_json = Json.to_string (body_json manifest) in
          let digest = "sha256:" ^ Sha256.digest_string unsigned_json in
          let manifest = { manifest with canonical_json = ""; digest } in
          let manifest =
            { manifest with canonical_json = Json.to_string (to_json manifest) }
          in
          match validate_symlinks entries with
          | Error _ as error -> error
          | Ok () -> Ok manifest)
      | (path, source) :: rest -> (
          match relative_to ~root path with
          | Error _ as error -> error
          | Ok relative -> (
              match
                if generated_relative relative then Some "product-default"
                else
                  Option.map
                    (fun _ -> "trusted-policy")
                    (excluded_by trusted_exclusions relative)
              with
              | Some reason ->
                  collect paths portable identities total entries
                    ({ path = relative; reason } :: exclusions)
                    rest
              | None ->
                  let folded = String.lowercase_ascii relative in
                  if List.mem relative paths then
                    Error ("duplicate source manifest path: " ^ relative)
                  else if List.mem folded portable then
                    Error ("portable case-fold path collision: " ^ relative)
                  else if List.length entries >= budget.max_entries then
                    Error
                      "Incomplete.Resource_limit: source entry budget exceeded"
                  else
                    let kind, executable, size, digest, target, identity =
                      match source with
                      | Regular_source { contents; executable; identity } ->
                          ( Regular,
                            executable,
                            Int64.of_int (String.length contents),
                            "sha256:" ^ Sha256.digest_string contents,
                            None,
                            identity )
                      | Symlink_source { target; identity } -> (
                          match resolve_target relative target with
                          | Error message ->
                              raise
                                (Invalid_argument (relative ^ ": " ^ message))
                          | Ok resolved ->
                              ( Symlink,
                                false,
                                Int64.of_int (String.length target),
                                "sha256:" ^ Sha256.digest_string target,
                                Some resolved,
                                identity ))
                    in
                    if size > Int64.of_int budget.max_file_bytes then
                      Error
                        ("Incomplete.Resource_limit: file exceeds 16 MiB: "
                       ^ relative)
                    else if Int64.add total size > budget.max_snapshot_bytes
                    then
                      Error "Incomplete.Resource_limit: snapshot exceeds 4 GiB"
                    else if
                      Option.fold ~none:false
                        ~some:(fun value -> List.mem value identities)
                        identity
                    then Error ("hardlink/file identity collision: " ^ relative)
                    else
                      collect (relative :: paths) (folded :: portable)
                        (Option.to_list identity @ identities)
                        (Int64.add total size)
                        ({
                           path = relative;
                           kind;
                           executable;
                           size;
                           digest;
                           target;
                           identity;
                         }
                        :: entries)
                        exclusions rest))
    in
    try
      files
      |> List.sort (fun (left, _) (right, _) ->
          String.compare (normalize left) (normalize right))
      |> collect [] [] [] 0L [] []
    with Invalid_argument message -> Error message

let create ~root ~files =
  let files =
    files
    |> List.map (fun (path, contents) ->
        (path, Regular_source { contents; executable = false; identity = None }))
  in
  create_from_sources ~budget:default_budget ~trusted_exclusions:[] ~root ~files
