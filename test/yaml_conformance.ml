type case = {
  id : string;
  directory : string;
  input : string;
  expected_events : string option;
  expects_error : bool;
}

let fail format =
  Printf.ksprintf
    (fun message ->
      prerr_endline message;
      exit 2)
    format

let read path =
  match Util.read_file path with
  | Ok value -> value
  | Error message -> fail "%s" message

let rec case_directories root relative accumulator =
  let directory =
    if relative = "" then root else Filename.concat root relative
  in
  let entries =
    Sys.readdir directory |> Array.to_list |> List.sort String.compare
  in
  if List.mem "in.yaml" entries then relative :: accumulator
  else
    List.fold_left
      (fun state name ->
        let child_relative =
          if relative = "" then name else Filename.concat relative name
        in
        let child = Filename.concat root child_relative in
        if Sys.is_directory child then
          case_directories root child_relative state
        else state)
      accumulator entries

let load_case suite relative =
  let directory = Filename.concat suite relative in
  let event_path = Filename.concat directory "test.event" in
  {
    id =
      String.map
        (function
          | '\\' -> '/'
          | character -> character)
        relative;
    directory;
    input = read (Filename.concat directory "in.yaml");
    expected_events =
      (if Sys.file_exists event_path then Some (read event_path) else None);
    expects_error = Sys.file_exists (Filename.concat directory "error");
  }

let normalize_newline source =
  source
  |> Util.replace_all ~needle:"\r\n" ~replacement:"\n"
  |> Util.replace_all ~needle:"\r" ~replacement:"\n"

let fatal_problem (problem : Yaml_cst.problem) =
  List.mem problem.code [ "YAML-SYNTAX"; "YAML-TAB-INDENT" ]

let evaluate case =
  let tree =
    Yaml_cst.parse ~file:(Filename.concat case.directory "in.yaml") case.input
  in
  let rejected = List.exists fatal_problem tree.problems in
  if case.expects_error then
    if rejected then Ok () else Error "invalid input was accepted"
  else if rejected then
    Error
      ("valid input was rejected: "
      ^ String.concat ", "
          (List.map
             (fun p ->
               p.Yaml_cst.code ^ " at " ^ Span.to_string p.span ^ " ("
               ^ p.message ^ ")")
             tree.problems))
  else
    match case.expected_events with
    | None -> Error "valid case has no test.event"
    | Some expected ->
        let actual = Yaml_event.of_cst tree |> Yaml_event.to_string in
        if normalize_newline expected = normalize_newline actual then Ok ()
        else
          Error
            ("event stream differs\nexpected:\n" ^ expected ^ "actual:\n"
           ^ actual)

let parse_arguments () =
  let suite = ref None
  and audit = ref false
  and verbose = ref false
  and list_failures = ref false
  and selected = ref None in
  let specification =
    [
      ( "--suite",
        Arg.String (fun value -> suite := Some value),
        "PATH test-data checkout" );
      ( "--audit",
        Arg.Set audit,
        "Report failures without returning a failing status" );
      ("--verbose", Arg.Set verbose, "Print every failing case");
      ( "--case",
        Arg.String (fun value -> selected := Some value),
        "ID Run one case" );
      ( "--list-failures",
        Arg.Set list_failures,
        "Print every failure as ID and category" );
    ]
  in
  Arg.parse specification
    (fun value -> fail "unexpected argument: %s" value)
    "yaml_conformance --suite PATH [--audit] [--verbose]";
  ( (match !suite with
    | Some value -> value
    | None -> fail "--suite is required"),
    !audit,
    !verbose,
    !list_failures,
    !selected )

let () =
  let suite, audit, verbose, list_failures, selected = parse_arguments () in
  if not (Sys.file_exists suite && Sys.is_directory suite) then
    fail "suite directory does not exist: %s" suite;
  let cases =
    case_directories suite "" []
    |> List.sort String.compare
    |> List.map (load_case suite)
    |> List.filter (fun case ->
        Option.fold ~none:true ~some:(String.equal case.id) selected)
  in
  if cases = [] then fail "suite contains no in.yaml cases: %s" suite;
  let failures = ref [] in
  List.iter
    (fun case ->
      match evaluate case with
      | Ok () -> ()
      | Error reason -> failures := (case.id, reason) :: !failures)
    cases;
  let failures = List.rev !failures in
  let passed = List.length cases - List.length failures in
  Printf.printf "yaml-test-suite: %d/%d passed (%d failed)\n%!" passed
    (List.length cases) (List.length failures);
  failures
  |> List.iteri (fun index (id, reason) ->
      if list_failures then
        let category =
          match String.index_opt reason '\n' with
          | None -> reason
          | Some stop -> String.sub reason 0 stop
        in
        Printf.printf "%s\t%s\n%!" id category
      else if verbose || index < 20 then
        Printf.printf "not ok - %s: %s\n%!" id reason);
  if failures <> [] && not audit then exit 1
