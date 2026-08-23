exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let transport_contract () =
  let files = ref [] and removed = ref [] and observed_command = ref None in
  let counter = ref 0 in
  let temporary_file ~prefix ~suffix =
    incr counter;
    Printf.sprintf "C:/temp/%s%d%s" prefix !counter suffix
  in
  let system =
    {
      Process_transport.temporary_file;
      write_file =
        (fun path contents ->
          files := (path, contents) :: List.remove_assoc path !files;
          Ok ());
      read_file =
        (fun path ->
          match List.assoc_opt path !files with
          | Some source -> Ok source
          | None -> Error ("missing " ^ path));
      remove_file = (fun path -> removed := path :: !removed);
      command =
        (fun command ->
          observed_command := Some command;
          let stdout = "C:/temp/workflow-verifier-helper-2.stdout" in
          let stderr = "C:/temp/workflow-verifier-helper-3.stderr" in
          files := (stdout, "result") :: (stderr, "warning") :: !files;
          7);
    }
  in
  let request =
    {
      Helper_client.executable = "C:/Program Files/helper.exe";
      arguments = [ "--source"; "C:/repo & hostile" ];
      stdin = "canonical plan";
    }
  in
  let response =
    match Process_transport.invoke system request with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  let expected_command =
    Filename.quote_command request.executable request.arguments
      ~stdin:"C:/temp/workflow-verifier-helper-1.stdin"
      ~stdout:"C:/temp/workflow-verifier-helper-2.stdout"
      ~stderr:"C:/temp/workflow-verifier-helper-3.stderr"
  in
  expect "transport uses the standard cross-platform argv quoter"
    (!observed_command = Some expected_command);
  expect "transport preserves status and separate output channels"
    (response.exit_code = 7 && response.stdout = "result"
    && response.stderr = "warning");
  expect "transport writes canonical stdin before execution"
    (List.assoc_opt "C:/temp/workflow-verifier-helper-1.stdin" !files
    = Some "canonical plan");
  expect "all private transport files are cleaned up"
    (List.sort String.compare !removed
    = [
        "C:/temp/workflow-verifier-helper-1.stdin";
        "C:/temp/workflow-verifier-helper-2.stdout";
        "C:/temp/workflow-verifier-helper-3.stderr";
      ])

let () =
  try
    transport_contract ();
    Printf.printf "ok - process transport is quoted and transactional\n%!"
  with
  | Failed message ->
      Printf.eprintf "not ok - process transport: %s\n%!" message;
      exit 1
  | error ->
      Printf.eprintf "not ok - process transport: unexpected %s\n%!"
        (Printexc.to_string error);
      exit 1
