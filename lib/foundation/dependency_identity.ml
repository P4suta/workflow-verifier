type classification = Local | Immutable | Mutable | Unknown

let is_hex = function
  | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true
  | _ -> false

let exact_hex length value =
  String.length value = length && String.for_all is_hex value

let valid_content_digest value =
  let prefix = "sha256:" in
  String.length value = String.length prefix + 64
  && Util.starts_with ~prefix value
  && exact_hex 64 (String.sub value (String.length prefix) 64)

let immutable_revision revision =
  exact_hex 40 revision || exact_hex 64 revision
  || valid_content_digest revision

let classify_reference reference =
  if
    Util.starts_with ~prefix:"./" reference
    || Util.starts_with ~prefix:"../" reference
  then Local
  else
    match String.rindex_opt reference '@' with
    | Some index ->
        let revision =
          String.sub reference (index + 1) (String.length reference - index - 1)
        in
        if immutable_revision revision then Immutable else Mutable
    | None -> if Util.contains ~needle:"://" reference then Mutable else Unknown
