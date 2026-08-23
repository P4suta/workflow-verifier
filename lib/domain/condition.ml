type truth = False | True | Unknown
type t = Bottom | Top | Branch of { variable : string; low : t; high : t }

let false_ = Bottom
let true_ = Top
let equal = ( = )

let branch variable low high =
  if equal low high then low else Branch { variable; low; high }

let atom variable = branch variable Bottom Top

let rec not_ = function
  | Bottom -> Top
  | Top -> Bottom
  | Branch node -> branch node.variable (not_ node.low) (not_ node.high)

type operation = And | Or

let terminal operation left right =
  match (operation, left, right) with
  | And, Bottom, _ | And, _, Bottom -> Some Bottom
  | And, Top, value | And, value, Top -> Some value
  | Or, Top, _ | Or, _, Top -> Some Top
  | Or, Bottom, value | Or, value, Bottom -> Some value
  | _ when equal left right -> Some left
  | _ -> None

let rec apply operation left right =
  match terminal operation left right with
  | Some value -> value
  | None -> (
      match (left, right) with
      | Branch left_node, Branch right_node ->
          let comparison =
            String.compare left_node.variable right_node.variable
          in
          if comparison = 0 then
            branch left_node.variable
              (apply operation left_node.low right_node.low)
              (apply operation left_node.high right_node.high)
          else if comparison < 0 then
            branch left_node.variable
              (apply operation left_node.low right)
              (apply operation left_node.high right)
          else
            branch right_node.variable
              (apply operation left right_node.low)
              (apply operation left right_node.high)
      | Branch node, terminal ->
          branch node.variable
            (apply operation node.low terminal)
            (apply operation node.high terminal)
      | terminal, Branch node ->
          branch node.variable
            (apply operation terminal node.low)
            (apply operation terminal node.high)
      | _ -> assert false)

let and_ = apply And
let or_ = apply Or
let satisfiable value = value <> Bottom

let implies premise conclusion =
  not (satisfiable (and_ premise (not_ conclusion)))

let rec evaluate lookup = function
  | Bottom -> False
  | Top -> True
  | Branch node -> (
      match lookup node.variable with
      | Some false -> evaluate lookup node.low
      | Some true -> evaluate lookup node.high
      | None ->
          let low = evaluate lookup node.low
          and high = evaluate lookup node.high in
          if low = high then low else Unknown)

let atoms value =
  let rec collect accumulator = function
    | Bottom | Top -> accumulator
    | Branch node ->
        collect (collect (node.variable :: accumulator) node.low) node.high
  in
  collect [] value |> Util.deduplicate_strings

let rec to_json = function
  | Bottom -> Json.Bool false
  | Top -> Json.Bool true
  | Branch node ->
      Json.Object
        [
          ("high", to_json node.high);
          ("low", to_json node.low);
          ("variable", Json.String node.variable);
        ]

let to_string value =
  let rec formula = function
    | Bottom -> "false"
    | Top -> "true"
    | Branch { variable; low = Bottom; high = Top } -> variable
    | Branch node ->
        Printf.sprintf "((not %s and %s) or (%s and %s))" node.variable
          (formula node.low) node.variable (formula node.high)
  in
  formula value
