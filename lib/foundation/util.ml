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
  try
    let directory = Filename.dirname path in
    mkdir_p directory;
    let channel = open_out_bin path in
    Fun.protect
      ~finally:(fun () -> close_out_noerr channel)
      (fun () ->
        output_string channel contents;
        flush channel;
        Ok ())
  with Sys_error message -> Error message

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
