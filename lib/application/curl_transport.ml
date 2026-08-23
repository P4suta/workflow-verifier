let valid_header_name value =
  value <> ""
  && String.for_all
       (function
         | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' -> true
         | _ -> false)
       value

let safe_text value =
  not
    (String.exists
       (function
         | '\r' | '\n' | '\000' -> true
         | _ -> false)
       value)

let validate request =
  if not (safe_text request.Resolver_transport.url) then
    Error "curl URL contains a control character"
  else
    match
      List.find_opt
        (fun (name, value) ->
          (not (valid_header_name name)) || not (safe_text value))
        request.headers
    with
    | Some _ -> Error "curl header contains an invalid name or value"
    | None -> Ok ()

let error_response response =
  let detail = String.trim response.Helper_client.stderr in
  let detail =
    if String.length detail <= 4096 then detail
    else String.sub detail 0 4096 ^ "..."
  in
  if detail = "" then Printf.sprintf "curl exited %d" response.exit_code
  else Printf.sprintf "curl exited %d: %s" response.exit_code detail

let make ~invoke ~executable request =
  match validate request with
  | Error _ as error -> error
  | Ok () -> (
      let header_arguments =
        request.headers
        |> List.concat_map (fun (name, value) ->
            [ "--header"; name ^ ": " ^ value ])
      in
      let arguments =
        [
          "--disable";
          "--silent";
          "--show-error";
          "--fail";
          "--proto";
          "=https";
          "--proto-redir";
          "=https";
          "--tlsv1.2";
          "--connect-timeout";
          "15";
          "--max-time";
          "120";
          "--max-filesize";
          "16777216";
          "--request";
          "GET";
          "--user-agent";
          "workflow-verifier/0.1.0-dev";
        ]
        @ header_arguments @ [ "--url"; request.url ]
      in
      match invoke { Helper_client.executable; arguments; stdin = "" } with
      | Error _ as error -> error
      | Ok response when response.Helper_client.exit_code <> 0 ->
          Error (error_response response)
      | Ok response ->
          Ok
            {
              Resolver_transport.status = 200;
              body = response.Helper_client.stdout;
              effective_url = request.url;
            })
