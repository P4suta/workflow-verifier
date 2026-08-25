type system = {
  getenv : string -> string option;
  run :
    executable:string ->
    arguments:string list ->
    environment:(string * string) list ->
    stdin:string ->
    timeout_seconds:int ->
    output_bytes:int ->
    (Helper_client.response, string) result;
}

val invoke : system -> Helper_client.invoke
