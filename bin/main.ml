let system_io =
  {
    Cli.cwd = Sys.getcwd;
    read_file = Util.read_file;
    write_file = Util.write_file;
    exists = Sys.file_exists;
    is_directory =
      (fun path -> try Sys.is_directory path with Sys_error _ -> false);
    list_files = Util.files_recursively;
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
