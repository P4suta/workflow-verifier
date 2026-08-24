type state =
  | Proved
  | Violated
  | Unknown of Unknown.reason list
  | Not_applicable

type t = {
  id : string;
  state : state;
  subject : string option;
  explanation : string;
}

let state_name = function
  | Proved -> "Proved"
  | Violated -> "Violated"
  | Unknown _ -> "Unknown"
  | Not_applicable -> "NotApplicable"

let state_rank = function
  | Proved -> 0
  | Violated -> 1
  | Unknown _ -> 2
  | Not_applicable -> 3

let compare_state left right =
  match (left, right) with
  | Unknown left, Unknown right ->
      Stdlib.compare
        (List.sort Unknown.compare left)
        (List.sort Unknown.compare right)
  | _ -> Int.compare (state_rank left) (state_rank right)

let compare left right =
  match String.compare left.id right.id with
  | 0 -> (
      match Option.compare String.compare left.subject right.subject with
      | 0 -> (
          match compare_state left.state right.state with
          | 0 -> String.compare left.explanation right.explanation
          | comparison -> comparison)
      | comparison -> comparison)
  | comparison -> comparison

let combine states =
  if List.exists (( = ) Violated) states then Violated
  else
    let unknowns =
      List.concat_map
        (function
          | Unknown reasons -> reasons
          | _ -> [])
        states
      |> Util.deduplicate_compare Unknown.compare
    in
    if unknowns <> [] then Unknown unknowns
    else if List.exists (( = ) Proved) states then Proved
    else Not_applicable

let to_json property =
  let reasons =
    match property.state with
    | Unknown reasons -> Json.Array (List.map Unknown.to_json reasons)
    | _ -> Json.Array []
  in
  Json.Object
    [
      ("explanation", Json.String property.explanation);
      ("id", Json.String property.id);
      ("reasons", reasons);
      ("state", Json.String (state_name property.state));
      ( "subject",
        Option.fold ~none:Json.Null
          ~some:(fun value -> Json.String value)
          property.subject );
    ]
