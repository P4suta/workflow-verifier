let ( let* ) result f =
  match result with
  | Ok value -> f value
  | Error _ as error -> error

let ( let+ ) result f =
  match result with
  | Ok value -> Ok (f value)
  | Error _ as error -> error

let trim = String.trim

let starts_with ~prefix value =
  let prefix_length = String.length prefix in
  String.length value >= prefix_length
  && String.sub value 0 prefix_length = prefix

let ends_with ~suffix value =
  let value_length = String.length value
  and suffix_length = String.length suffix in
  value_length >= suffix_length
  && String.sub value (value_length - suffix_length) suffix_length = suffix

let contains ~needle haystack =
  let needle_length = String.length needle
  and haystack_length = String.length haystack in
  let rec search index =
    if needle_length = 0 then true
    else if index + needle_length > haystack_length then false
    else if String.sub haystack index needle_length = needle then true
    else search (index + 1)
  in
  search 0

let split_once character value =
  match String.index_opt value character with
  | None -> (value, None)
  | Some index ->
      ( String.sub value 0 index,
        Some (String.sub value (index + 1) (String.length value - index - 1)) )

let rec list_filter_map f = function
  | [] -> []
  | head :: tail -> (
      match f head with
      | None -> list_filter_map f tail
      | Some value -> value :: list_filter_map f tail)

let deduplicate_compare compare values =
  let sorted = List.sort compare values in
  let rec loop previous accumulator = function
    | [] -> List.rev accumulator
    | head :: tail -> (
        match previous with
        | Some old when compare old head = 0 -> loop previous accumulator tail
        | _ -> loop (Some head) (head :: accumulator) tail)
  in
  loop None [] sorted

let deduplicate_strings = deduplicate_compare String.compare

let rec mkdir_p path =
  if path = "" || path = "." || Sys.file_exists path then ()
  else (
    mkdir_p (Filename.dirname path);
    Sys.mkdir path 0o755)

let read_file path =
  try
    let channel = open_in_bin path in
    Fun.protect
      ~finally:(fun () -> close_in_noerr channel)
      (fun () ->
        let length = in_channel_length channel in
        really_input_string channel length |> Result.ok)
  with Sys_error message -> Error message

let write_file path contents =
  let temporary = ref None in
  let cleanup () =
    match !temporary with
    | Some candidate when Sys.file_exists candidate -> (
        try Sys.remove candidate with Sys_error _ -> ())
    | Some _ | None -> ()
  in
  try
    let directory = Filename.dirname path in
    mkdir_p directory;
    let mode =
      try
        let metadata = Unix.lstat path in
        if metadata.st_kind = Unix.S_LNK then
          raise (Sys_error (path ^ ": refusing to replace a symbolic link"));
        if metadata.st_kind <> Unix.S_REG then
          raise (Sys_error (path ^ ": refusing to replace a non-regular file"));
        metadata.st_perm
      with Unix.Unix_error (Unix.ENOENT, _, _) -> 0o600
    in
    let prefix = "." ^ Filename.basename path ^ ".workflow-verifier-" in
    let candidate, channel =
      Filename.open_temp_file ~temp_dir:directory prefix ".tmp"
        ~mode:[ Open_binary; Open_wronly; Open_excl ]
    in
    temporary := Some candidate;
    let wrote =
      Fun.protect
        ~finally:(fun () -> close_out_noerr channel)
        (fun () ->
          output_string channel contents;
          flush channel;
          Unix.fsync (Unix.descr_of_out_channel channel);
          Unix.chmod candidate mode;
          Ok ())
    in
    match wrote with
    | Error _ as error -> error
    | Ok () ->
        Unix.rename candidate path;
        temporary := None;
        (if not Sys.win32 then
           let descriptor = Unix.openfile directory [ Unix.O_RDONLY ] 0 in
           Fun.protect
             ~finally:(fun () -> Unix.close descriptor)
             (fun () -> Unix.fsync descriptor));
        Ok ()
  with
  | Sys_error message ->
      cleanup ();
      Error message
  | Unix.Unix_error (code, operation, target) ->
      cleanup ();
      Error
        (Printf.sprintf "%s %s: %s" operation target (Unix.error_message code))

let normalize_slashes path =
  String.map
    (function
      | '\\' -> '/'
      | character -> character)
    path

let path_join left right =
  if left = "" || left = "." then right else Filename.concat left right

let extension_lower path = String.lowercase_ascii (Filename.extension path)

let rec files_recursively root =
  if not (Sys.file_exists root) then []
  else if not (Sys.is_directory root) then [ root ]
  else
    Sys.readdir root |> Array.to_list |> List.sort String.compare
    |> List.concat_map (fun name ->
        files_recursively (Filename.concat root name))

let replace_all ~needle ~replacement value =
  if needle = "" then value
  else
    let buffer = Buffer.create (String.length value) in
    let needle_length = String.length needle in
    let rec loop offset =
      if offset >= String.length value then ()
      else if
        offset + needle_length <= String.length value
        && String.sub value offset needle_length = needle
      then (
        Buffer.add_string buffer replacement;
        loop (offset + needle_length))
      else (
        Buffer.add_char buffer value.[offset];
        loop (offset + 1))
    in
    loop 0;
    Buffer.contents buffer

let lowercase = String.lowercase_ascii

let option_value ~default = function
  | Some value -> value
  | None -> default

let rec take count values =
  if count <= 0 then []
  else
    match values with
    | [] -> []
    | head :: tail -> head :: take (count - 1) tail

let rec take_while predicate = function
  | head :: tail when predicate head -> head :: take_while predicate tail
  | _ -> []

let string_of_file_error path message = Printf.sprintf "%s: %s" path message

let valid_utf8 value =
  let length = String.length value in
  let continuation index =
    index < length
    &&
    let byte = Char.code value.[index] in
    byte >= 0x80 && byte <= 0xbf
  in
  let rec loop index =
    if index = length then true
    else
      let first = Char.code value.[index] in
      if first <= 0x7f then loop (index + 1)
      else if first >= 0xc2 && first <= 0xdf then
        continuation (index + 1) && loop (index + 2)
      else if first = 0xe0 then
        index + 2 < length
        &&
        let second = Char.code value.[index + 1] in
        second >= 0xa0 && second <= 0xbf
        && continuation (index + 2)
        && loop (index + 3)
      else if
        (first >= 0xe1 && first <= 0xec) || (first >= 0xee && first <= 0xef)
      then
        continuation (index + 1) && continuation (index + 2) && loop (index + 3)
      else if first = 0xed then
        index + 2 < length
        &&
        let second = Char.code value.[index + 1] in
        second >= 0x80 && second <= 0x9f
        && continuation (index + 2)
        && loop (index + 3)
      else if first = 0xf0 then
        index + 3 < length
        &&
        let second = Char.code value.[index + 1] in
        second >= 0x90 && second <= 0xbf
        && continuation (index + 2)
        && continuation (index + 3)
        && loop (index + 4)
      else if first >= 0xf1 && first <= 0xf3 then
        continuation (index + 1)
        && continuation (index + 2)
        && continuation (index + 3)
        && loop (index + 4)
      else if first = 0xf4 then
        index + 3 < length
        &&
        let second = Char.code value.[index + 1] in
        second >= 0x80 && second <= 0x8f
        && continuation (index + 2)
        && continuation (index + 3)
        && loop (index + 4)
      else false
  in
  loop 0
