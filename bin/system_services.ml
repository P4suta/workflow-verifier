let platform =
  match Sys.os_type with
  | "Win32" | "Cygwin" -> "windows"
  | "Unix" ->
      if Sys.file_exists "/System/Library/CoreServices/SystemVersion.plist" then
        "macos"
      else "linux"
  | value -> String.lowercase_ascii value

let executable_suffix = if Sys.win32 then ".exe" else ""

type helper = { path : string; digest : string }

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

let normalized_digest value =
  let value = String.trim value in
  let value =
    match String.split_on_char ' ' value with
    | first :: _ -> first
    | [] -> value
  in
  let value =
    if Util.starts_with ~prefix:"sha256:" value then
      String.sub value 7 (String.length value - 7)
    else value
  in
  if
    String.length value = 64
    && String.for_all
         (fun character ->
           (character >= '0' && character <= '9')
           || (character >= 'a' && character <= 'f'))
         value
  then Some ("sha256:" ^ value)
  else None

let expected_helper_digest path environment =
  match Sys.getenv_opt environment with
  | Some configured when configured = path ->
      Option.bind (Sys.getenv_opt (environment ^ "_SHA256")) normalized_digest
  | _ -> (
      match Util.read_file (path ^ ".sha256") with
      | Ok source -> normalized_digest source
      | Error _ -> None)

let find_helper name environment =
  helper_candidates name environment
  |> List.find_map (fun path ->
      if
        not
          (Sys.file_exists path
          && try not (Sys.is_directory path) with Sys_error _ -> false)
      then None
      else
        match
          (expected_helper_digest path environment, Sha256.digest_file path)
        with
        | Some expected, Ok actual when expected = "sha256:" ^ actual ->
            Some { path; digest = expected }
        | _ -> None)

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

let close_descriptor descriptor =
  try Unix.close descriptor with Unix.Unix_error _ -> ()

let pipe_reader descriptor total exceeded limit =
  let channel = Unix.in_channel_of_descr descriptor in
  set_binary_mode_in channel true;
  let output = Buffer.create 8192 and error = ref None in
  let rec loop buffer =
    match input channel buffer 0 (Bytes.length buffer) with
    | 0 -> ()
    | count ->
        let previous = Atomic.fetch_and_add total count in
        if previous < limit then
          Buffer.add_subbytes output buffer 0 (min count (limit - previous));
        if previous + count > limit then Atomic.set exceeded true;
        loop buffer
  in
  (try loop (Bytes.create 8192) with
  | Sys_error message -> error := Some message
  | Unix.Unix_error (code, operation, _) ->
      error := Some (operation ^ ": " ^ Unix.error_message code));
  close_in_noerr channel;
  (Buffer.contents output, !error)

let direct_run ~executable ~arguments ~environment ~stdin ~timeout_seconds
    ~output_bytes =
  let stdin_read, stdin_write = Unix.pipe ~cloexec:true ()
  and stdout_read, stdout_write = Unix.pipe ~cloexec:true ()
  and stderr_read, stderr_write = Unix.pipe ~cloexec:true () in
  let close_all () =
    List.iter close_descriptor
      [
        stdin_read;
        stdin_write;
        stdout_read;
        stdout_write;
        stderr_read;
        stderr_write;
      ]
  in
  let argv = Array.of_list (executable :: arguments)
  and environment =
    environment
    |> List.map (fun (name, value) -> name ^ "=" ^ value)
    |> Array.of_list
  in
  match
    try
      Ok
        (Unix.create_process_env executable argv environment stdin_read
           stdout_write stderr_write)
    with
    | Unix.Unix_error (code, operation, _) ->
        Error (operation ^ ": " ^ Unix.error_message code)
    | Sys_error message -> Error message
  with
  | Error message ->
      close_all ();
      Error message
  | Ok pid -> (
      close_descriptor stdin_read;
      close_descriptor stdout_write;
      close_descriptor stderr_write;
      let total = Atomic.make 0 and exceeded = Atomic.make false in
      let stdout_result = ref ("", None) and stderr_result = ref ("", None) in
      let stdout_thread =
        Thread.create
          (fun () ->
            stdout_result := pipe_reader stdout_read total exceeded output_bytes)
          ()
      and stderr_thread =
        Thread.create
          (fun () ->
            stderr_result := pipe_reader stderr_read total exceeded output_bytes)
          ()
      and stdin_thread =
        Thread.create
          (fun () ->
            let channel = Unix.out_channel_of_descr stdin_write in
            set_binary_mode_out channel true;
            (try output_string channel stdin with Sys_error _ -> ());
            close_out_noerr channel)
          ()
      in
      let deadline = Unix.gettimeofday () +. float_of_int timeout_seconds in
      let timed_out = ref false in
      let killed_for_output = ref false in
      let rec await () =
        match Unix.waitpid [ Unix.WNOHANG ] pid with
        | 0, _ ->
            if Atomic.get exceeded then (
              killed_for_output := true;
              (try Unix.kill pid Sys.sigkill with Unix.Unix_error _ -> ());
              snd (Unix.waitpid [] pid))
            else if Unix.gettimeofday () >= deadline then (
              timed_out := true;
              (try Unix.kill pid Sys.sigkill with Unix.Unix_error _ -> ());
              snd (Unix.waitpid [] pid))
            else (
              Thread.delay 0.01;
              await ())
        | _, status -> status
      in
      let status = await () in
      Thread.join stdin_thread;
      Thread.join stdout_thread;
      Thread.join stderr_thread;
      let stdout, stdout_error = !stdout_result
      and stderr, stderr_error = !stderr_result in
      match (stdout_error, stderr_error) with
      | Some message, _ | _, Some message -> Error message
      | _ when !timed_out ->
          Error
            (Printf.sprintf "process exceeded %d second wall timeout"
               timeout_seconds)
      | _ when !killed_for_output ->
          Error
            (Printf.sprintf "combined process output exceeded %d bytes"
               output_bytes)
      | _ ->
          let exit_code =
            match status with
            | Unix.WEXITED code -> code
            | Unix.WSIGNALED signal | Unix.WSTOPPED signal -> 128 + signal
          in
          Ok { Helper_client.exit_code; stdout; stderr })

let process_system =
  { Process_transport.getenv = Sys.getenv_opt; run = direct_run }

let invoke = Process_transport.invoke process_system

let verify_helper helper =
  match Sha256.digest_file helper.path with
  | Ok actual when helper.digest = "sha256:" ^ actual -> Ok ()
  | Ok _ -> Error ("sandbox helper digest changed: " ^ helper.path)
  | Error message -> Error message

let oci_probe helper engine =
  match verify_helper helper with
  | Error _ as error -> error
  | Ok () ->
      Helper_client.probe ~invoke ~executable:helper.path
        ~arguments:[ "--doctor"; "--engine"; engine ]

let oci_execute helper ~source_root plan =
  match (verify_helper helper, plan.Sandbox_protocol.backend) with
  | Error message, _ -> Error message
  | Ok (), Sandbox_protocol.Oci engine ->
      Helper_client.execute ~invoke ~executable:helper.path
        ~arguments:[ "--run"; "--engine"; engine; "--source"; source_root ]
        plan
  | Ok (), backend ->
      Error
        (Printf.sprintf "OCI helper cannot execute backend %s"
           (Sandbox_protocol.backend_name backend))

let native_probe helper expected_id =
  match verify_helper helper with
  | Error _ -> None
  | Ok () -> (
      match
        Helper_client.probe ~invoke ~executable:helper.path
          ~arguments:[ "--doctor" ]
      with
      | Ok ({ attestation; _ } as probe) when attestation.id = expected_id ->
          Some probe
      | Ok _ | Error _ -> None)

type helpers = {
  oci : helper option;
  linux : helper option;
  windows : helper option;
  macos : helper option;
}

let native_execute helper ~source_root plan =
  match verify_helper helper with
  | Error _ as error -> error
  | Ok () ->
      Helper_client.execute ~invoke ~executable:helper.path
        ~arguments:[ "--run"; "--source"; source_root ]
        plan

let unavailable_probe id reason =
  {
    Sandbox_backend.available = false;
    attestation = { id; version = "unavailable"; platform; controls = [] };
    reasons = [ reason ];
  }

let inventory probe helper required_features =
  {
    Cli.probe;
    path = Option.map (fun helper -> helper.path) helper;
    digest = Option.map (fun helper -> helper.digest) helper;
    signature = (if Option.is_some helper then "trusted-digest" else "absent");
    protocol = "backend-attestation-v1/runner-v2/evidence-v2";
    required_features;
  }

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
    [ "docker"; "podman" ]
    |> List.map (fun engine ->
        let id = "oci:" ^ engine in
        match helpers.oci with
        | None ->
            unavailable_probe id
              "OCI helper is absent or lacks its explicit trusted digest"
        | Some helper -> (
            match oci_probe helper engine with
            | Ok probe -> probe
            | Error message -> unavailable_probe id message))
  in
  let native_probes =
    [
      ( "linux-native",
        helpers.linux,
        [ "landlock-abi"; "namespace"; "seccomp"; "cgroup-v2"; "network-deny" ]
      );
      ( "windows-native",
        helpers.windows,
        [ "app-container"; "restricted-token"; "job-object"; "network-deny" ] );
      ( "macos-vm",
        helpers.macos,
        [
          "virtualization-framework";
          "boot-bundle";
          "guest-agent";
          "network-deny";
        ] );
    ]
    |> List.map (fun (id, helper, _features) ->
        match helper with
        | None ->
            unavailable_probe id
              "sandbox helper is absent or lacks its explicit trusted digest"
        | Some helper -> (
            match native_probe helper id with
            | Some probe -> probe
            | None ->
                unavailable_probe id
                  "helper probe failed or protocol identity mismatched"))
  in
  let backend_probes = oci_probes @ native_probes in
  let native_inventory =
    List.map2
      (fun probe (_id, helper, features) -> inventory probe helper features)
      native_probes
      [
        ( "linux-native",
          helpers.linux,
          [
            "landlock-abi"; "namespace"; "seccomp"; "cgroup-v2"; "network-deny";
          ] );
        ( "windows-native",
          helpers.windows,
          [ "app-container"; "restricted-token"; "job-object"; "network-deny" ]
        );
        ( "macos-vm",
          helpers.macos,
          [
            "virtualization-framework";
            "boot-bundle";
            "guest-agent";
            "network-deny";
          ] );
      ]
  in
  let oci_inventory =
    List.map
      (fun probe ->
        inventory probe helpers.oci
          [ "OCI engine"; "digest-pinned capsule"; "network-deny" ])
      oci_probes
  in
  let has_executor =
    List.exists (fun probe -> probe.Sandbox_backend.available) backend_probes
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
    backend_probes;
    backend_inventory = oci_inventory @ native_inventory;
  }
