type request = {
  backend : Sandbox_protocol.backend;
  required_controls : Sandbox_protocol.control list;
}

type attestation = {
  id : string;
  version : string;
  platform : string;
  controls : Sandbox_protocol.control list;
}

type probe = {
  available : bool;
  attestation : attestation;
  reasons : string list;
}

val select :
  request ->
  attestation list ->
  (attestation, Sandbox_protocol.control list) result

val attestation_to_json : attestation -> Json.t
val probe_to_json : probe -> Json.t
val parse_probe : string -> (probe, string) result
