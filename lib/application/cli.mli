type source_snapshot = {
  manifest : Source_manifest.t;
  files : (string * string) list;
}

type backend_inventory = {
  probe : Sandbox_backend.probe;
  path : string option;
  digest : string option;
  signature : string;
  protocol : string;
  required_features : string list;
}

type io = {
  cwd : unit -> string;
  today : unit -> string;
  user_cache_dir : unit -> string option;
  read_file : string -> (string, string) result;
  write_file : string -> string -> (unit, string) result;
  remove_file : string -> (unit, string) result;
  exists : string -> bool;
  is_directory : string -> bool;
  list_files : string -> string list;
  snapshot :
    trusted_exclusions:string list -> string -> (source_snapshot, string) result;
  binary_digest : unit -> string;
  source_commit : unit -> string option;
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
  backend_inventory : backend_inventory list;
}

val run : io:io -> services:services -> string array -> int
