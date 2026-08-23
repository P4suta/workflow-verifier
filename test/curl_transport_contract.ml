type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let argv_safe_get_test () =
  let observed = ref None in
  let invoke request =
    observed := Some request;
    Ok { Helper_client.exit_code = 0; stdout = "binary\000body"; stderr = "" }
  in
  let get = Curl_transport.make ~invoke ~executable:"curl" in
  let response =
    match
      get
        {
          Resolver_transport.url = "https://api.github.com/start";
          headers = [ ("Accept", "application/json") ];
        }
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "binary response bytes are preserved" (response.body = "binary\000body");
  expect "a successful non-redirecting transfer is a 200 response"
    (response.status = 200
    && response.effective_url = "https://api.github.com/start");
  match !observed with
  | None -> fail "curl was not invoked"
  | Some request ->
      expect "curl receives no stdin" (request.Helper_client.stdin = "");
      expect "URL remains one argv element"
        (List.mem "https://api.github.com/start" request.arguments);
      List.iter
        (fun required ->
          expect ("curl omits " ^ required)
            (List.mem required request.arguments))
        [
          "--disable";
          "--proto";
          "=https";
          "--proto-redir";
          "--max-filesize";
          "--fail";
        ];

      expect "curl never follows redirects"
        (not (List.mem "--location" request.arguments))

let header_boundary_test () =
  let calls = ref 0 in
  let invoke _ =
    incr calls;
    Ok { Helper_client.exit_code = 0; stdout = "body"; stderr = "" }
  in
  let get = Curl_transport.make ~invoke ~executable:"curl" in
  let injected =
    get
      {
        Resolver_transport.url = "https://example.test";
        headers = [ ("Accept", "ok\r\nX-Evil: yes") ];
      }
  in
  expect "header injection is rejected before process invocation"
    (Result.is_error injected && !calls = 0)

let nonzero_exit_test () =
  let invoke _ =
    Ok { Helper_client.exit_code = 28; stdout = ""; stderr = "curl: timeout\n" }
  in
  let get = Curl_transport.make ~invoke ~executable:"curl" in
  match
    get { Resolver_transport.url = "https://example.test"; headers = [] }
  with
  | Ok _ -> fail "nonzero curl exit was accepted"
  | Error message ->
      expect "transport error retains the actionable curl failure"
        (Util.contains ~needle:"timeout" message)

let tests =
  [
    ( "curl adapter is argv-safe and keeps metadata out of content",
      argv_safe_get_test );
    ( "curl adapter rejects malformed headers before launch",
      header_boundary_test );
    ("curl adapter reports transport exits", nonzero_exit_test);
  ]

let () =
  let failures = ref 0 in
  List.iter
    (fun (name, run) ->
      try
        run ();
        Printf.printf "ok - %s\n%!" name
      with
      | Failed message ->
          incr failures;
          Printf.eprintf "not ok - %s: %s\n%!" name message
      | error ->
          incr failures;
          Printf.eprintf "not ok - %s: unexpected %s\n%!" name
            (Printexc.to_string error))
    tests;
  if !failures > 0 then exit 1
