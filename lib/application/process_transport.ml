type system = {
  getenv : string -> string option;
  run :
    executable:string ->
    arguments:string list ->
    environment:(string * string) list ->
    stdin:string ->
    timeout_seconds:int ->
    output_bytes:int ->
    (Helper_client.response, string) result;
}

let safe_value value =
  not (String.exists (fun character -> character = '\000') value)

let base_environment_names =
  [
    "PATH";
    "SystemRoot";
    "WINDIR";
    "COMSPEC";
    "PATHEXT";
    "TEMP";
    "TMP";
    "TMPDIR";
    "HOME";
    "USERPROFILE";
    "LANG";
    "LC_ALL";
    "SSL_CERT_FILE";
    "SSL_CERT_DIR";
    "DOCKER_HOST";
    "CONTAINER_HOST";
    "WORKFLOW_VERIFIER_CGROUP_ROOT";
    "WORKFLOW_VERIFIER_MACOS_VM_BUNDLE";
    "WORKFLOW_VERIFIER_MACOS_VM_MANIFEST_DIGEST";
    "WORKFLOW_VERIFIER_MACOS_VM_SHIM";
  ]

let declared_secret_names stdin =
  match Sandbox_protocol.parse stdin with
  | Ok plan -> plan.secret_names
  | Error _ -> []

let environment system secret_names =
  base_environment_names @ secret_names
  |> Util.deduplicate_strings
  |> List.filter_map (fun name ->
      match system.getenv name with
      | Some value when safe_value value -> Some (name, value)
      | Some _ | None -> None)

let redact secret_values value =
  List.fold_left
    (fun output secret ->
      if secret = "" then output
      else Util.replace_all ~needle:secret ~replacement:"***" output)
    value secret_values

let invoke system (request : Helper_client.request) =
  if String.trim request.executable = "" then
    Error "process executable is empty"
  else if
    (not (safe_value request.executable))
    || List.exists (fun argument -> not (safe_value argument)) request.arguments
  then Error "process argv contains a NUL byte"
  else if String.length request.stdin > 16 * 1024 * 1024 then
    Error "process stdin exceeds 16 MiB"
  else
    let secret_names = declared_secret_names request.stdin in
    let environment = environment system secret_names in
    let secret_values =
      secret_names
      |> List.filter_map (fun name -> List.assoc_opt name environment)
    in
    try
      match
        system.run ~executable:request.executable ~arguments:request.arguments
          ~environment ~stdin:request.stdin ~timeout_seconds:120
          ~output_bytes:(16 * 1024 * 1024)
      with
      | Error _ as error -> error
      | Ok response ->
          Ok
            {
              response with
              Helper_client.stdout = redact secret_values response.stdout;
              stderr = redact secret_values response.stderr;
            }
    with error ->
      Error ("process transport failure: " ^ Printexc.to_string error)
