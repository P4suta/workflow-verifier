type request = { executable : string; arguments : string list; stdin : string }
type response = { exit_code : int; stdout : string; stderr : string }
type invoke = request -> (response, string) result

val probe :
  invoke:invoke ->
  executable:string ->
  arguments:string list ->
  (Sandbox_backend.probe, string) result

val execute :
  invoke:invoke ->
  executable:string ->
  arguments:string list ->
  Sandbox_protocol.plan ->
  (Sandbox_run.t, string) result
