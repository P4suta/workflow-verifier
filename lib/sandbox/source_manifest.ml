type entry = { path : string; digest : string }
type t = { entries : entry list; canonical_json : string; digest : string }

let generated_directories =
  [
    ".git";
    ".workflow-verifier-cache";
    "_build";
    "_opam";
    "node_modules";
    "target";
  ]

let normalize = Util.normalize_slashes

let normalized_root root =
  let root = normalize root in
  if root <> "." && root <> "" && Util.ends_with ~suffix:"/" root then
    String.sub root 0 (String.length root - 1)
  else root

let relative_to ~root path =
  let root = normalized_root root and path = normalize path in
  if root = "." || root = "" then Ok path
  else if path = root then Error "source manifest entries must be files"
  else
    let prefix = root ^ "/" in
    if Util.starts_with ~prefix path then
      Ok
        (String.sub path (String.length prefix)
           (String.length path - String.length prefix))
    else Error (Printf.sprintf "source path escapes manifest root: %s" path)

let generated_relative path =
  path |> String.lowercase_ascii |> String.split_on_char '/'
  |> List.exists (fun segment -> List.mem segment generated_directories)

let is_generated ~root path =
  match relative_to ~root path with
  | Ok relative -> generated_relative relative
  | Error _ -> false

let entry_json (entry : entry) =
  Json.Object
    [ ("digest", Json.String entry.digest); ("path", Json.String entry.path) ]

let create ~root ~files =
  let rec collect seen accumulator = function
    | [] -> Ok (List.rev accumulator)
    | (path, contents) :: rest -> (
        match relative_to ~root path with
        | Error _ as error -> error
        | Ok relative ->
            if relative = "" then Error "source manifest path cannot be empty"
            else if generated_relative relative then
              collect seen accumulator rest
            else if List.mem relative seen then
              Error
                (Printf.sprintf "duplicate source manifest path: %s" relative)
            else
              collect (relative :: seen)
                ({
                   path = relative;
                   digest = "sha256:" ^ Sha256.digest_string contents;
                 }
                :: accumulator)
                rest)
  in
  match
    files
    |> List.sort (fun (left, _) (right, _) ->
        String.compare (normalize left) (normalize right))
    |> collect [] []
  with
  | Error _ as error -> error
  | Ok entries ->
      let canonical_json =
        entries |> List.map entry_json |> fun values ->
        Json.to_string (Json.Array values)
      in
      Ok
        {
          entries;
          canonical_json;
          digest = "sha256:" ^ Sha256.digest_string canonical_json;
        }
