type invocation = { command : string; arguments : string list }

type outcome =
  | Invoke of invocation
  | Help of string
  | Version of string
  | Error of string

val parse : argv:string array -> outcome
