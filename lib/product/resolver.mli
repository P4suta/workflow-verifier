type semantic_source = { path : string; content : string }

type fetched = {
  revision : string;
  content : string;
  source : string;
  semantic_source : semantic_source option;
}

type network = { fetch : Frontend_intf.dependency -> (fetched, string) result }

type result = {
  locked : (Frontend_intf.dependency * Lockfile.entry) list;
  unresolved : Frontend_intf.dependency list;
  errors : string list;
  lockfile : Lockfile.t;
}

val resolve :
  ?allowed_sources:string list ->
  ?refresh:bool ->
  network:network option ->
  lock:Lockfile.t ->
  Frontend_intf.dependency list ->
  result
