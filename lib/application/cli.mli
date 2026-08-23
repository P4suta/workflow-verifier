type io = {
  cwd : unit -> string;
  read_file : string -> (string, string) result;
  write_file : string -> string -> (unit, string) result;
  exists : string -> bool;
  is_directory : string -> bool;
  list_files : string -> string list;
  stdout : string -> unit;
  stderr : string -> unit;
}

type services = {
  resolver_network : (allowed_sources:string list -> Resolver.network) option;
  sandbox_execute :
    (source_root:string ->
    Sandbox_protocol.plan ->
    (Sandbox_run.t, string) result)
    option;
  platform : string;
  backend_probes : Sandbox_backend.probe list;
}

val run : io:io -> services:services -> string array -> int
val help : string
