type style = Literal | Folded
type chomping = Clip | Keep | Strip

type header = {
  style : style;
  chomping : chomping;
  indentation : int option;
}

type classification = Not_block | Valid of header | Invalid of int

val classify : string -> classification
