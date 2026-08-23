type system = {
  temporary_file : prefix:string -> suffix:string -> string;
  write_file : string -> string -> (unit, string) result;
  read_file : string -> (string, string) result;
  remove_file : string -> unit;
  command : string -> int;
}

let invoke system (request : Helper_client.request) =
  let temporary_paths = ref [] in
  let temporary_file suffix =
    let path =
      system.temporary_file ~prefix:"workflow-verifier-helper-" ~suffix
    in
    temporary_paths := path :: !temporary_paths;
    path
  and cleanup () =
    List.iter
      (fun path -> try system.remove_file path with _ -> ())
      !temporary_paths
  in
  try
    let result =
      Fun.protect ~finally:cleanup (fun () ->
          let stdin_path = temporary_file ".stdin"
          and stdout_path = temporary_file ".stdout"
          and stderr_path = temporary_file ".stderr" in
          match system.write_file stdin_path request.stdin with
          | Error _ as error -> error
          | Ok () -> (
              let command =
                Filename.quote_command request.executable request.arguments
                  ~stdin:stdin_path ~stdout:stdout_path ~stderr:stderr_path
              in
              let exit_code = system.command command in
              match system.read_file stdout_path with
              | Error _ as error -> error
              | Ok stdout -> (
                  match system.read_file stderr_path with
                  | Error _ as error -> error
                  | Ok stderr -> Ok { Helper_client.exit_code; stdout; stderr })
              ))
    in
    result
  with error ->
    cleanup ();
    Error ("helper transport failure: " ^ Printexc.to_string error)
