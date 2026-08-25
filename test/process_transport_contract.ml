exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let transport_contract () =
  let observed = ref None in
  let system =
    {
      Process_transport.getenv =
        (fun name -> if name = "PATH" then Some "C:/Tools" else None);
      run =
        (fun ~executable
          ~arguments
          ~environment
          ~stdin
          ~timeout_seconds
          ~output_bytes
        ->
          observed :=
            Some
              ( executable,
                arguments,
                environment,
                stdin,
                timeout_seconds,
                output_bytes );
          Ok
            {
              Helper_client.exit_code = 7;
              stdout = "result";
              stderr = "warning";
            });
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
  expect "transport preserves the executable and argv as separate values"
    (!observed
    = Some
        ( request.executable,
          request.arguments,
          [ ("PATH", "C:/Tools") ],
          request.stdin,
          120,
          16 * 1024 * 1024 ));
  expect "transport preserves status and separate output channels"
    (response.exit_code = 7 && response.stdout = "result"
    && response.stderr = "warning");
  expect "NUL bytes are rejected before process creation"
    (match
       Process_transport.invoke system
         { request with arguments = [ "safe"; "bad\000argument" ] }
     with
    | Error _ -> true
    | Ok _ -> false)

let () =
  try
    transport_contract ();
    Printf.printf
      "ok - process transport is direct argv, piped, bounded, and \
       environment-limited\n\
       %!"
  with
  | Failed message ->
      Printf.eprintf "not ok - process transport: %s\n%!" message;
      exit 1
  | error ->
      Printf.eprintf "not ok - process transport: unexpected %s\n%!"
        (Printexc.to_string error);
      exit 1
