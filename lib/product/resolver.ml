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

let valid_hex_length length value =
  String.length value = length
  && String.for_all
       (function
         | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true
         | _ -> false)
       value

let immutable_revision provider revision =
  valid_hex_length 40 revision
  || valid_hex_length 64 revision
  || Util.starts_with ~prefix:"sha256:" revision
     && String.length revision = 71
     && valid_hex_length 64 (String.sub revision 7 64)
  ||
  match provider with
  | Ir.Circleci ->
      revision <> ""
      && String.for_all
           (function
             | '0' .. '9' | '.' | '-' | '+' -> true
             | _ -> false)
           revision
  | Azure ->
      let compact = Util.replace_all ~needle:"-" ~replacement:"" revision in
      valid_hex_length 32 compact
  | Github | Gitlab -> false

let source_allowed allowed source =
  allowed = []
  || List.exists (fun prefix -> Util.starts_with ~prefix source) allowed

let resolve ?(allowed_sources = []) ?(refresh = false) ~network ~lock
    dependencies =
  let locked = ref []
  and unresolved = ref []
  and errors = ref []
  and current_lock = ref lock in
  dependencies
  |> List.sort
       (fun
         (left : Frontend_intf.dependency) (right : Frontend_intf.dependency) ->
         match
           String.compare
             (Ir.provider_name left.Frontend_intf.provider)
             (Ir.provider_name right.provider)
         with
         | 0 -> String.compare left.reference right.reference
         | comparison -> comparison)
  |> List.iter (fun (dependency : Frontend_intf.dependency) ->
      if dependency.mutability = Frontend_intf.Local then
        match dependency.status with
        | Locked _ -> ()
        | Unresolved _ -> unresolved := dependency :: !unresolved
      else
        match
          if refresh then None
          else
            Lockfile.find !current_lock dependency.Frontend_intf.provider
              dependency.reference
        with
        | Some entry -> locked := (dependency, entry) :: !locked
        | None -> (
            match network with
            | None -> unresolved := dependency :: !unresolved
            | Some adapter -> (
                match adapter.fetch dependency with
                | Error message ->
                    errors :=
                      Printf.sprintf "%s: %s" dependency.reference message
                      :: !errors;
                    unresolved := dependency :: !unresolved
                | Ok fetched -> (
                    if
                      not
                        (immutable_revision dependency.provider fetched.revision)
                    then (
                      errors :=
                        (dependency.reference
                       ^ ": resolver returned a mutable revision "
                       ^ fetched.revision)
                        :: !errors;
                      unresolved := dependency :: !unresolved)
                    else if not (source_allowed allowed_sources fetched.source)
                    then (
                      errors :=
                        (dependency.reference
                       ^ ": resolved source is outside the allowlist")
                        :: !errors;
                      unresolved := dependency :: !unresolved)
                    else
                      let entry =
                        {
                          Lockfile.provider = dependency.provider;
                          reference = dependency.reference;
                          revision = fetched.revision;
                          digest =
                            "sha256:" ^ Sha256.digest_string fetched.content;
                          source = fetched.source;
                          summary =
                            Option.map
                              (fun semantic_source ->
                                Dependency_summary.infer dependency
                                  ~path:semantic_source.path
                                  ~source:semantic_source.content)
                              fetched.semantic_source;
                        }
                      in
                      let entries =
                        entry
                        :: List.filter
                             (fun existing ->
                               existing.Lockfile.provider <> entry.provider
                               || existing.reference <> entry.reference)
                             !current_lock.entries
                      in
                      match Lockfile.create entries with
                      | Error message ->
                          errors :=
                            Printf.sprintf "%s: %s" dependency.reference message
                            :: !errors;
                          unresolved := dependency :: !unresolved
                      | Ok lockfile ->
                          current_lock := lockfile;
                          locked := (dependency, entry) :: !locked))));
  {
    locked = List.rev !locked;
    unresolved = List.rev !unresolved;
    errors = List.rev !errors;
    lockfile = !current_lock;
  }
