type request = { executable : string; arguments : string list; stdin : string }
type response = { exit_code : int; stdout : string; stderr : string }
type invoke = request -> (response, string) result

let response_error response =
  let detail = String.trim response.stderr in
  if detail = "" then Printf.sprintf "helper exited %d" response.exit_code
  else Printf.sprintf "helper exited %d: %s" response.exit_code detail

let call ~invoke ~executable ~arguments ~stdin parse =
  match invoke { executable; arguments; stdin } with
  | Error _ as error -> error
  | Ok response when response.exit_code <> 0 -> Error (response_error response)
  | Ok response -> parse response.stdout

let probe ~invoke ~executable ~arguments =
  call ~invoke ~executable ~arguments ~stdin:"" Sandbox_backend.parse_probe

let execute ~invoke ~executable ~arguments plan =
  call ~invoke ~executable ~arguments
    ~stdin:(Sandbox_protocol.to_canonical_json plan)
    Sandbox_run.parse
