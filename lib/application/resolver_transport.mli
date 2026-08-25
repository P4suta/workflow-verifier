type request = { url : string; headers : (string * string) list }

type response = {
  status : int;
  body : string;
  effective_url : string;
  peer_ip : string;
}

type get = request -> (response, string) result

val make : get:get -> allowed_sources:string list -> Resolver.network
