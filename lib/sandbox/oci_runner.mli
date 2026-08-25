type process_result = {
  exit_code : int option;
  timed_out : bool;
  output_truncated : bool;
  redacted_secrets : string list;
  redacted_output : string;
  wall_time_ms : int;
  output_bytes : int;
}

type scratch_result = { digest : string; bytes : int64; entries : int }

type runtime = {
  prepare_scratch :
    source_root:string -> scratch_root:string -> (unit, string) result;
  finalize_scratch : scratch_root:string -> (scratch_result, string) result;
  run :
    engine:string ->
    arguments:string list ->
    timeout_seconds:int ->
    output_bytes:int ->
    secret_names:string list ->
    (process_result, string) result;
}

val execute :
  runtime:runtime ->
  source_root:string ->
  scratch_root:string ->
  Sandbox_protocol.plan ->
  (Sandbox_run.t, string) result
