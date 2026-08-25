let normalized_path path =
  let value = Util.normalize_slashes path in
  if Sys.win32 then String.lowercase_ascii value else value

let confined ~root path =
  let root = normalized_path root and path = normalized_path path in
  path = root || Util.starts_with ~prefix:(root ^ "/") path

let file_identity metadata =
  if metadata.Unix.st_ino = 0 then None
  else Some (Printf.sprintf "%d:%d" metadata.st_dev metadata.st_ino)

let same_identity left right =
  left.Unix.st_dev = right.Unix.st_dev
  && left.st_ino = right.st_ino
  && left.st_kind = right.st_kind

let safe_source_snapshot ~trusted_exclusions root =
  let budget = Source_manifest.default_budget in
  let sources = ref [] and files = ref [] and directories = ref [] in
  let entries = ref 0 and total = ref 0L in
  let root_real = ref "" in
  let add_entry relative =
    incr entries;
    if !entries > budget.max_entries then
      raise
        (Sys_error
           ("Incomplete.Resource_limit: source entry budget exceeded at "
          ^ relative))
  in
  let logical relative =
    if relative = "" then root else Util.path_join root relative
  in
  let rec visit relative current =
    if
      relative <> ""
      && Source_manifest.is_excluded ~root ~trusted_exclusions
           (logical relative)
    then (
      add_entry relative;
      sources :=
        ( logical relative,
          Source_manifest.Regular_source
            { contents = ""; executable = false; identity = None } )
        :: !sources)
    else
      let before = Unix.lstat current in
      if relative <> "" then add_entry relative;
      match before.st_kind with
      | Unix.S_DIR ->
          let followed = Unix.stat current in
          if not (same_identity before followed) then
            raise
              (Sys_error (logical relative ^ ": reparse directory rejected"));
          let canonical = Unix.realpath current in
          if not (confined ~root:!root_real canonical) then
            raise
              (Sys_error (logical relative ^ ": directory escapes snapshot root"));
          let identity =
            file_identity before |> Option.value ~default:canonical
          in
          if List.mem identity !directories then
            raise (Sys_error (logical relative ^ ": directory cycle detected"));
          directories := identity :: !directories;
          let names =
            Sys.readdir current |> Array.to_list |> List.sort String.compare
          in
          List.iter
            (fun name ->
              if not (Util.valid_utf8 name) then
                raise
                  (Sys_error (logical relative ^ ": non-UTF-8 directory entry"));
              let child_relative =
                if relative = "" then name else relative ^ "/" ^ name
              in
              visit child_relative (Filename.concat current name))
            names;
          let after = Unix.lstat current in
          if not (same_identity before after) then
            raise
              (Sys_error
                 (logical relative ^ ": directory changed during snapshot"));
          directories :=
            List.filter (fun value -> value <> identity) !directories
      | Unix.S_REG ->
          if before.st_size > budget.max_file_bytes then
            raise
              (Sys_error
                 ("Incomplete.Resource_limit: file exceeds 16 MiB: "
                ^ logical relative));
          let projected = Int64.add !total (Int64.of_int before.st_size) in
          if projected > budget.max_snapshot_bytes then
            raise
              (Sys_error "Incomplete.Resource_limit: snapshot exceeds 4 GiB");
          let channel = open_in_bin current in
          let contents =
            Fun.protect
              ~finally:(fun () -> close_in_noerr channel)
              (fun () ->
                let opened = Unix.fstat (Unix.descr_of_in_channel channel) in
                if not (same_identity before opened) then
                  raise
                    (Sys_error
                       (logical relative ^ ": file identity changed before read"));
                let contents = really_input_string channel before.st_size in
                let after = Unix.fstat (Unix.descr_of_in_channel channel) in
                if
                  (not (same_identity opened after))
                  || after.st_size <> opened.st_size
                  || after.st_mtime <> opened.st_mtime
                  || after.st_ctime <> opened.st_ctime
                then
                  raise
                    (Sys_error
                       (logical relative ^ ": file changed during snapshot"));
                contents)
          in
          total := projected;
          let path = logical relative in
          files := (path, contents) :: !files;
          sources :=
            ( path,
              Source_manifest.Regular_source
                {
                  contents;
                  executable = before.st_perm land 0o111 <> 0;
                  identity = file_identity before;
                } )
            :: !sources
      | Unix.S_LNK ->
          let target = Unix.readlink current in
          sources :=
            ( logical relative,
              Source_manifest.Symlink_source
                { target; identity = file_identity before } )
            :: !sources
      | Unix.S_CHR | Unix.S_BLK | Unix.S_FIFO | Unix.S_SOCK ->
          raise
            (Sys_error (logical relative ^ ": special source entry is forbidden"))
  in
  try
    root_real := Unix.realpath root;
    let root_metadata = Unix.lstat root in
    if root_metadata.st_kind <> Unix.S_DIR then
      Error (root ^ ": snapshot root must be a real directory")
    else (
      visit "" root;
      match
        Source_manifest.create_from_sources ~budget ~trusted_exclusions ~root
          ~files:(List.rev !sources)
      with
      | Error _ as error -> error
      | Ok manifest ->
          Ok
            {
              Cli.manifest;
              files =
                List.rev !files
                |> List.sort (fun (left, _) (right, _) ->
                    String.compare (normalized_path left)
                      (normalized_path right));
            })
  with
  | Sys_error message -> Error message
  | Unix.Unix_error (code, operation, target) ->
      Error
        (Printf.sprintf "%s %s: %s" operation target (Unix.error_message code))

let system_io =
  let today () =
    let time = Unix.gmtime (Unix.gettimeofday ()) in
    Printf.sprintf "%04d-%02d-%02d" (time.tm_year + 1900) (time.tm_mon + 1)
      time.tm_mday
  in
  {
    Cli.cwd = Sys.getcwd;
    today;
    user_cache_dir =
      (fun () ->
        let candidates =
          if Sys.win32 then
            [ Sys.getenv_opt "LOCALAPPDATA"; Sys.getenv_opt "APPDATA" ]
          else
            [
              Sys.getenv_opt "XDG_CACHE_HOME";
              Option.map
                (fun home -> Filename.concat home ".cache")
                (Sys.getenv_opt "HOME");
            ]
        in
        List.find_map
          (function
            | Some value when String.trim value <> "" -> Some value
            | _ -> None)
          candidates);
    read_file = Util.read_file;
    write_file = Util.write_file;
    remove_file =
      (fun path ->
        try
          if Sys.file_exists path then
            let metadata = Unix.lstat path in
            if metadata.st_kind <> Unix.S_REG then
              Error (path ^ ": refusing to remove a non-regular file")
            else (
              Sys.remove path;
              Ok ())
          else Ok ()
        with
        | Sys_error message -> Error message
        | Unix.Unix_error (code, operation, target) ->
            Error
              (Printf.sprintf "%s %s: %s" operation target
                 (Unix.error_message code)));
    exists = Sys.file_exists;
    is_directory =
      (fun path -> try Sys.is_directory path with Sys_error _ -> false);
    list_files =
      (fun root ->
        match safe_source_snapshot ~trusted_exclusions:[] root with
        | Ok snapshot -> List.map fst snapshot.Cli.files
        | Error _ -> []);
    snapshot = safe_source_snapshot;
    binary_digest =
      (fun () ->
        match Util.read_file Sys.executable_name with
        | Ok source -> "sha256:" ^ Sha256.digest_string source
        | Error _ ->
            "sha256:"
            ^ Sha256.digest_string ("unavailable-binary:" ^ Sys.executable_name));
    source_commit =
      (fun () ->
        match Sys.getenv_opt "WORKFLOW_VERIFIER_SOURCE_COMMIT" with
        | Some value
          when let length = String.length value in
               (length = 40 || length = 64)
               && String.for_all
                    (function
                      | '0' .. '9' | 'a' .. 'f' -> true
                      | _ -> false)
                    value -> Some value
        | Some _ | None -> None);
    stdout =
      (fun text ->
        output_string stdout text;
        flush stdout);
    stderr =
      (fun text ->
        output_string stderr text;
        flush stderr);
  }

let () =
  set_binary_mode_out stdout true;
  set_binary_mode_out stderr true;
  exit (Cli.run ~io:system_io ~services:(System_services.make ()) Sys.argv)
