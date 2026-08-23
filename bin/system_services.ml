let platform =
  match Sys.os_type with
  | "Win32" | "Cygwin" -> "windows"
  | "Unix" ->
      if Sys.file_exists "/System/Library/CoreServices/SystemVersion.plist" then
        "macos"
      else "linux"
  | value -> String.lowercase_ascii value

let executable_suffix = if Sys.win32 then ".exe" else ""

let helper_candidates name environment =
  let configured =
    match Sys.getenv_opt environment with
    | Some path when String.trim path <> "" -> [ path ]
    | _ -> []
  in
  let executable_directory = Filename.dirname Sys.executable_name in
  let filename = name ^ executable_suffix in
  configured
  @ [
      Filename.concat executable_directory filename;
      Filename.concat
        (Filename.concat
           (Filename.concat executable_directory "..")
           "libexec/workflow-verifier")
        filename;
    ]

let find_helper name environment =
  helper_candidates name environment
  |> List.find_opt (fun path ->
      Sys.file_exists path
      && try not (Sys.is_directory path) with Sys_error _ -> false)

let is_executable_file path =
  Sys.file_exists path
  && try not (Sys.is_directory path) with Sys_error _ -> false

let find_program name environment =
  match Sys.getenv_opt environment with
  | Some path when String.trim path <> "" ->
      if is_executable_file path then Some path else None
  | _ ->
      let filenames =
        if Sys.win32 && Filename.extension name = "" then
          [ name ^ ".exe"; name ]
        else [ name ]
      in
      let directories =
        Sys.getenv_opt "PATH"
        |> Option.map (String.split_on_char (if Sys.win32 then ';' else ':'))
        |> Option.value ~default:[]
        |> List.filter (fun path -> path <> "")
      in
      directories
      |> List.find_map (fun directory ->
          filenames
          |> List.find_map (fun filename ->
              let path = Filename.concat directory filename in
              if is_executable_file path then Some path else None))

let read_file_limited limit path =
  try
    let channel = open_in_bin path in
    Fun.protect
      ~finally:(fun () -> close_in_noerr channel)
      (fun () ->
        let length = in_channel_length channel in
        if length > limit then
          Error (Printf.sprintf "helper response exceeds %d bytes" limit)
        else Ok (really_input_string channel length))
  with Sys_error message -> Error message

let process_system =
  {
    Process_transport.temporary_file =
      (fun ~prefix ~suffix -> Filename.temp_file prefix suffix);
    write_file = Util.write_file;
    read_file = read_file_limited (16 * 1024 * 1024);
    remove_file =
      (fun path ->
        if Sys.file_exists path then try Sys.remove path with _ -> ());
    command = Sys.command;
  }

let invoke = Process_transport.invoke process_system

let oci_probe helper engine =
  Helper_client.probe ~invoke ~executable:helper
    ~arguments:[ "--doctor"; "--engine"; engine ]

let oci_execute helper ~source_root plan =
  match plan.Sandbox_protocol.backend with
  | Sandbox_protocol.Oci engine ->
      Helper_client.execute ~invoke ~executable:helper
        ~arguments:[ "--run"; "--engine"; engine; "--source"; source_root ]
        plan
  | backend ->
      Error
        (Printf.sprintf "OCI helper cannot execute backend %s"
           (Sandbox_protocol.backend_name backend))

let native_probe helper expected_id =
  match
    Helper_client.probe ~invoke ~executable:helper ~arguments:[ "--doctor" ]
  with
  | Ok ({ attestation; _ } as probe) when attestation.id = expected_id ->
      Some probe
  | Ok _ | Error _ -> None

type helpers = {
  oci : string option;
  linux : string option;
  windows : string option;
  macos : string option;
}

let native_execute helper ~source_root plan =
  Helper_client.execute ~invoke ~executable:helper
    ~arguments:[ "--run"; "--source"; source_root ]
    plan

let execute helpers ~source_root plan =
  let unavailable () =
    Error
      ("sandbox helper is unavailable for "
      ^ Sandbox_protocol.backend_name plan.Sandbox_protocol.backend)
  in
  match plan.backend with
  | Oci _ -> (
      match helpers.oci with
      | Some helper -> oci_execute helper ~source_root plan
      | None -> unavailable ())
  | Linux_native -> (
      match helpers.linux with
      | Some helper -> native_execute helper ~source_root plan
      | None -> unavailable ())
  | Windows_native -> (
      match helpers.windows with
      | Some helper -> native_execute helper ~source_root plan
      | None -> unavailable ())
  | Macos_vm -> (
      match helpers.macos with
      | Some helper -> native_execute helper ~source_root plan
      | None -> unavailable ())

let make () =
  let helpers =
    {
      oci =
        find_helper "workflow-verifier-oci-helper"
          "WORKFLOW_VERIFIER_OCI_HELPER";
      linux =
        find_helper "workflow-verifier-linux-helper"
          "WORKFLOW_VERIFIER_LINUX_HELPER";
      windows =
        find_helper "workflow-verifier-windows-helper"
          "WORKFLOW_VERIFIER_WINDOWS_HELPER";
      macos =
        find_helper "workflow-verifier-macos-helper"
          "WORKFLOW_VERIFIER_MACOS_HELPER";
    }
  in
  let oci_probes =
    match helpers.oci with
    | None -> []
    | Some helper ->
        [ "docker"; "podman" ]
        |> List.filter_map (fun engine ->
            match oci_probe helper engine with
            | Ok probe -> Some probe
            | Error _ -> None)
  in
  let native_probes =
    [
      Option.bind helpers.linux (fun helper ->
          native_probe helper "linux-native");
      Option.bind helpers.windows (fun helper ->
          native_probe helper "windows-native");
      Option.bind helpers.macos (fun helper -> native_probe helper "macos-vm");
    ]
    |> List.filter_map Fun.id
  in
  let has_executor =
    List.exists Option.is_some
      [ helpers.oci; helpers.linux; helpers.windows; helpers.macos ]
  in
  let resolver_network =
    find_program "curl" "WORKFLOW_VERIFIER_CURL"
    |> Option.map (fun executable ->
        let get = Curl_transport.make ~invoke ~executable in
        fun ~allowed_sources -> Resolver_transport.make ~get ~allowed_sources)
  in
  {
    Cli.resolver_network;
    sandbox_execute = (if has_executor then Some (execute helpers) else None);
    platform;
    backend_probes = oci_probes @ native_probes;
  }
