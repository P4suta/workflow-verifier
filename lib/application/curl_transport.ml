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

let quote_config value =
  let buffer = Buffer.create (String.length value + 2) in
  Buffer.add_char buffer '"';
  String.iter
    (function
      | ('"' | '\\') as character ->
          Buffer.add_char buffer '\\';
          Buffer.add_char buffer character
      | character -> Buffer.add_char buffer character)
    value;
  Buffer.add_char buffer '"';
  Buffer.contents buffer

let metadata_prefix = "workflow-verifier-curl-meta-v1\t"

let parse_metadata stderr =
  stderr |> String.split_on_char '\n' |> List.rev
  |> List.find_map (fun line ->
      if Util.starts_with ~prefix:metadata_prefix line then
        match String.split_on_char '\t' line with
        | [ _; status; effective_url; peer_ip ] -> (
            match int_of_string_opt status with
            | Some status
              when status >= 100 && status <= 599 && safe_text effective_url
                   && safe_text peer_ip -> Some (status, effective_url, peer_ip)
            | Some _ | None -> None)
        | _ -> None
      else None)

let config request =
  let headers =
    request.Resolver_transport.headers
    |> List.map (fun (name, value) ->
        "header = " ^ quote_config (name ^ ": " ^ value))
  in
  String.concat "\n" (headers @ [ "url = " ^ quote_config request.url ]) ^ "\n"

let make ~invoke ~executable request =
  match validate request with
  | Error _ as error -> error
  | Ok () -> (
      let arguments =
        [
          "--disable";
          "--silent";
          "--show-error";
          "--fail-with-body";
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
          Product_version.user_agent;
          "--write-out";
          "\n%{stderr}" ^ metadata_prefix
          ^ "%{http_code}\t%{url_effective}\t%{remote_ip}\n";
          "--config";
          "-";
        ]
      in
      match
        invoke { Helper_client.executable; arguments; stdin = config request }
      with
      | Error _ as error -> error
      | Ok response -> (
          match parse_metadata response.Helper_client.stderr with
          | Some (status, effective_url, peer_ip)
            when response.exit_code = 0 || response.exit_code = 22 ->
              Ok
                {
                  Resolver_transport.status;
                  body = response.stdout;
                  effective_url;
                  peer_ip;
                }
          | Some _ | None -> Error (error_response response)))
