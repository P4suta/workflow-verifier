type test = string * (unit -> unit)

exception Failed of string

let expect message condition = if not condition then raise (Failed message)

let classification_cases_test () =
  let open Dependency_identity in
  let cases =
    [
      ("./action", Local);
      ("../action", Local);
      ("owner/action@" ^ String.make 40 'a', Immutable);
      ("owner/action@" ^ String.make 64 'B', Immutable);
      ("docker://image@sha256:" ^ String.make 64 'c', Immutable);
      ("owner/action@v4", Mutable);
      ("owner/action@" ^ String.make 39 'd' ^ "z", Mutable);
      ("owner/action@" ^ String.make 38 'e', Mutable);
      ("docker://image:latest", Mutable);
      ("dynamic-call", Unknown);
    ]
  in
  List.iter
    (fun (reference, expected) ->
      expect
        ("unexpected classification for " ^ reference)
        (classify_reference reference = expected))
    cases

let digest_cases_test () =
  let valid = "sha256:" ^ String.make 64 'a' in
  expect "a canonical SHA-256 digest is valid"
    (Dependency_identity.valid_content_digest valid);
  expect "a short SHA-256 digest is invalid"
    (not
       (Dependency_identity.valid_content_digest
          ("sha256:" ^ String.make 63 'a')));
  expect "a non-hex SHA-256 digest is invalid"
    (not
       (Dependency_identity.valid_content_digest
          ("sha256:" ^ String.make 63 'a' ^ "z")));
  expect "uppercase SHA-256 text is non-canonical"
    (not
       (Dependency_identity.valid_content_digest
          ("sha256:" ^ String.make 64 'A')));
  expect "the digest algorithm is part of the identity"
    (not
       (Dependency_identity.valid_content_digest
          ("xha256:" ^ String.make 64 'a')))

let tests =
  [
    ( "dependency references have one canonical classification",
      classification_cases_test );
    ("content digests are exact SHA-256 identities", digest_cases_test);
  ]

let () =
  let failures = ref 0 in
  List.iter
    (fun (name, run) ->
      try
        run ();
        Printf.printf "ok - %s\n%!" name
      with
      | Failed message ->
          incr failures;
          Printf.eprintf "not ok - %s: %s\n%!" name message
      | error ->
          incr failures;
          Printf.eprintf "not ok - %s: unexpected %s\n%!" name
            (Printexc.to_string error))
    tests;
  if !failures > 0 then exit 1
