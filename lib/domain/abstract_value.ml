type value_type =
  | Never_type
  | Null_type
  | Bool_type
  | Number_type
  | String_type
  | List_type
  | Object_type
  | Dynamic_type

type truth = False | True | Maybe
type interval = { minimum : int64 option; maximum : int64 option }

type string_value =
  | Bottom
  | Constants of string list
  | Affix of { prefix : string option; suffix : string option }
  | Pattern of string
  | Top

type value =
  | Bottom_value
  | Null
  | Boolean of truth
  | Number of interval
  | String of string_value
  | List of t list option
  | Object of (string * t) list option
  | Unknown_value of Unknown.reason list

and trust = Trusted | Mixed | Untrusted | Unknown_trust of Unknown.reason list

and secrecy =
  | Public
  | Sensitive
  | Secret
  | Unknown_secrecy of Unknown.reason list

and provenance = { origin : string; span : Span.t; operation : string }

and t = {
  value_type : value_type;
  value : value;
  trust : trust;
  secrecy : secrecy;
  provenance : provenance list;
}

let bottom =
  {
    value_type = Never_type;
    value = Bottom_value;
    trust = Trusted;
    secrecy = Public;
    provenance = [];
  }

let string_constant value ~trust ~secrecy ~provenance =
  {
    value_type = String_type;
    value = String (Constants [ value ]);
    trust;
    secrecy;
    provenance;
  }

let unknown reason =
  {
    value_type = Dynamic_type;
    value = Unknown_value [ reason ];
    trust = Unknown_trust [ reason ];
    secrecy = Unknown_secrecy [ reason ];
    provenance = [];
  }

let join_type left right =
  if left = Never_type then right
  else if right = Never_type then left
  else if left = right then left
  else Dynamic_type

let reasons left right = Util.deduplicate_compare Unknown.compare (left @ right)

let join_trust left right =
  match (left, right) with
  | Untrusted, _ | _, Untrusted -> Untrusted
  | Unknown_trust left, Unknown_trust right ->
      Unknown_trust (reasons left right)
  | Unknown_trust values, _ | _, Unknown_trust values -> Unknown_trust values
  | Mixed, _ | _, Mixed -> Mixed
  | Trusted, Trusted -> Trusted

let join_secrecy left right =
  match (left, right) with
  | Secret, _ | _, Secret -> Secret
  | Unknown_secrecy left, Unknown_secrecy right ->
      Unknown_secrecy (reasons left right)
  | Unknown_secrecy values, _ | _, Unknown_secrecy values ->
      Unknown_secrecy values
  | Sensitive, _ | _, Sensitive -> Sensitive
  | Public, Public -> Public

let provenance_compare left right =
  match String.compare left.origin right.origin with
  | 0 -> (
      match Span.compare left.span right.span with
      | 0 -> String.compare left.operation right.operation
      | comparison -> comparison)
  | comparison -> comparison

let join_option_bound select left right =
  match (left, right) with
  | None, _ | _, None -> None
  | Some left, Some right -> Some (select left right)

let common_prefix left right =
  let limit = min (String.length left) (String.length right)
  and index = ref 0 in
  while !index < limit && left.[!index] = right.[!index] do
    incr index
  done;
  if !index = 0 then None else Some (String.sub left 0 !index)

let common_suffix left right =
  let left_length = String.length left and right_length = String.length right in
  let limit = min left_length right_length and count = ref 0 in
  while
    !count < limit
    && left.[left_length - !count - 1] = right.[right_length - !count - 1]
  do
    incr count
  done;
  if !count = 0 then None
  else Some (String.sub left (left_length - !count) !count)

let join_strings left right =
  match (left, right) with
  | Bottom, value | value, Bottom -> value
  | Top, _ | _, Top -> Top
  | Constants left, Constants right ->
      let values = Util.deduplicate_strings (left @ right) in
      if List.length values <= 8 then Constants values else Top
  | Constants [ left ], Affix { prefix; suffix }
  | Affix { prefix; suffix }, Constants [ left ] ->
      let prefix = Option.bind prefix (fun value -> common_prefix left value)
      and suffix = Option.bind suffix (fun value -> common_suffix left value) in
      if prefix = None && suffix = None then Top else Affix { prefix; suffix }
  | Affix left, Affix right ->
      let join_part common left right =
        match (left, right) with
        | Some left, Some right -> common left right
        | _ -> None
      in
      let prefix = join_part common_prefix left.prefix right.prefix
      and suffix = join_part common_suffix left.suffix right.suffix in
      if prefix = None && suffix = None then Top else Affix { prefix; suffix }
  | Pattern left, Pattern right when left = right -> Pattern left
  | _ -> Top

let rec join_value left right =
  match (left, right) with
  | Bottom_value, value | value, Bottom_value -> value
  | Null, Null -> Null
  | Boolean left, Boolean right ->
      Boolean (if left = right then left else Maybe)
  | Number left, Number right ->
      Number
        {
          minimum = join_option_bound Int64.min left.minimum right.minimum;
          maximum = join_option_bound Int64.max left.maximum right.maximum;
        }
  | String left, String right -> String (join_strings left right)
  | List (Some left), List (Some right)
    when List.length left = List.length right ->
      List (Some (List.map2 join left right))
  | List _, List _ -> List None
  | Object (Some left), Object (Some right) ->
      let keys =
        List.map fst left @ List.map fst right |> Util.deduplicate_strings
      in
      Object
        (Some
           (List.map
              (fun key ->
                let l = Option.value ~default:bottom (List.assoc_opt key left)
                and r =
                  Option.value ~default:bottom (List.assoc_opt key right)
                in
                (key, join l r))
              keys))
  | Object _, Object _ -> Object None
  | Unknown_value left, Unknown_value right ->
      Unknown_value (reasons left right)
  | Unknown_value values, _ | _, Unknown_value values ->
      (* A dynamic value joined with a concrete value is still an incompatible
         type join. Recording the same canonical reason on both paths keeps
         this operation associative, so fixed-point results cannot depend on
         work-list order. *)
      Unknown_value
        (reasons values
           [ Unknown.Unsupported_syntax "incompatible value join" ])
  | _ -> Unknown_value [ Unknown.Unsupported_syntax "incompatible value join" ]

and join left right =
  if left.value = Bottom_value then right
  else if right.value = Bottom_value then left
  else
    {
      value_type = join_type left.value_type right.value_type;
      value = join_value left.value right.value;
      trust = join_trust left.trust right.trust;
      secrecy = join_secrecy left.secrecy right.secrecy;
      provenance =
        Util.deduplicate_compare provenance_compare
          (left.provenance @ right.provenance);
    }

let map_trust trust value = { value with trust }
let map_secrecy secrecy value = { value with secrecy }
let is_untrusted value = value.trust = Untrusted
let is_secret value = value.secrecy = Secret

let constants value =
  match value.value with
  | String (Constants values) -> Some values
  | _ -> None

let type_name = function
  | Never_type -> "never"
  | Null_type -> "null"
  | Bool_type -> "bool"
  | Number_type -> "number"
  | String_type -> "string"
  | List_type -> "list"
  | Object_type -> "object"
  | Dynamic_type -> "dynamic"

let trust_json = function
  | Trusted -> Json.String "trusted"
  | Mixed -> Json.String "mixed"
  | Untrusted -> Json.String "untrusted"
  | Unknown_trust values ->
      Json.Object
        [
          ("reasons", Json.Array (List.map Unknown.to_json values));
          ("state", Json.String "unknown");
        ]

let secrecy_json = function
  | Public -> Json.String "public"
  | Sensitive -> Json.String "sensitive"
  | Secret -> Json.String "secret"
  | Unknown_secrecy values ->
      Json.Object
        [
          ("reasons", Json.Array (List.map Unknown.to_json values));
          ("state", Json.String "unknown");
        ]

let rec value_json = function
  | Bottom_value -> Json.String "bottom"
  | Null -> Json.Null
  | Boolean False -> Json.Bool false
  | Boolean True -> Json.Bool true
  | Boolean Maybe -> Json.String "maybe"
  | Number interval ->
      Json.Object
        [
          ( "maximum",
            Option.fold ~none:Json.Null
              ~some:(fun value -> Json.Int64 value)
              interval.maximum );
          ( "minimum",
            Option.fold ~none:Json.Null
              ~some:(fun value -> Json.Int64 value)
              interval.minimum );
        ]
  | String Bottom -> Json.String "bottom"
  | String (Constants values) ->
      Json.Object
        [
          ( "constants",
            Json.Array (List.map (fun value -> Json.String value) values) );
        ]
  | String (Affix { prefix; suffix }) ->
      Json.Object
        [
          ( "prefix",
            Option.fold ~none:Json.Null
              ~some:(fun value -> Json.String value)
              prefix );
          ( "suffix",
            Option.fold ~none:Json.Null
              ~some:(fun value -> Json.String value)
              suffix );
        ]
  | String (Pattern pattern) -> Json.Object [ ("pattern", Json.String pattern) ]
  | String Top -> Json.String "top"
  | List None -> Json.String "list-top"
  | List (Some values) ->
      Json.Array (List.map (fun value -> to_json value) values)
  | Object None -> Json.String "object-top"
  | Object (Some values) ->
      Json.Object (List.map (fun (key, value) -> (key, to_json value)) values)
  | Unknown_value values ->
      Json.Object [ ("unknown", Json.Array (List.map Unknown.to_json values)) ]

and to_json value =
  Json.Object
    [
      ( "provenance",
        Json.Array
          (List.map
             (fun item ->
               Json.Object
                 [
                   ("operation", Json.String item.operation);
                   ("origin", Json.String item.origin);
                   ("span", Span.to_json item.span);
                 ])
             value.provenance) );
      ("secrecy", secrecy_json value.secrecy);
      ("trust", trust_json value.trust);
      ("type", Json.String (type_name value.value_type));
      ("value", value_json value.value);
    ]
