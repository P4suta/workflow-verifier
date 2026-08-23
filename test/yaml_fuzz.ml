let fail format =
  Printf.ksprintf
    (fun message ->
      prerr_endline message;
      exit 1)
    format

let read_stdin limit =
  let buffer = Buffer.create 4096
  and chunk = Bytes.create 4096
  and total = ref 0 in
  let rec loop () =
    let count = input stdin chunk 0 (Bytes.length chunk) in
    if count = 0 then Buffer.contents buffer
    else (
      total := !total + count;
      if !total > limit then fail "fuzz input exceeds %d bytes" limit;
      Buffer.add_subbytes buffer chunk 0 count;
      loop ())
  in
  loop ()

let input () =
  let path = ref None in
  Arg.parse
    [
      ( "--input",
        Arg.String (fun value -> path := Some value),
        "PATH fuzz input" );
    ]
    (fun value -> fail "unexpected argument: %s" value)
    "yaml_fuzz [--input PATH]";
  match !path with
  | None -> read_stdin (1024 * 1024)
  | Some path -> (
      match Util.read_file path with
      | Error message -> fail "%s" message
      | Ok source when String.length source <= 1024 * 1024 -> source
      | Ok _ -> fail "fuzz input exceeds 1048576 bytes")

let () =
  Printexc.record_backtrace true;
  let source = input () in
  let first = Yaml_cst.parse ~file:"fuzz-input.yml" source in
  if Yaml_cst.print first <> source then
    fail "lossless round-trip changed source bytes";
  let second = Yaml_cst.parse ~file:"fuzz-input.yml" (Yaml_cst.print first) in
  if not (Yaml_cst.structural_equal first second) then
    fail "parse-print-parse changed the CST";
  let first_events = Yaml_event.of_cst first |> Yaml_event.to_string
  and second_events = Yaml_event.of_cst second |> Yaml_event.to_string in
  if first_events <> second_events then
    fail "parse-print-parse changed event projection"
