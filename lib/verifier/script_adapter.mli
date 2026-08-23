type shell =
  | Posix
  | Bash
  | PowerShell
  | Cmd
  | Python
  | Unknown_shell of string

type token = { text : string; quoted : bool; start : int; stop : int }

type expansion = {
  expansion_text : string;
  expansion_quoted : bool;
  expansion_start : int;
  expansion_stop : int;
}

type summary = {
  shell : shell;
  tokens : token list;
  capabilities : Ir.capability list;
  effects : Ir.observable_effect list;
  unknowns : Unknown.reason list;
  expansions : expansion list;
  unsafe_interpolation : bool;
  secret_to_network : bool;
  secret_to_output : bool;
}

val shell_name : shell -> string
val command_source : Ir.node -> string
val shell_of_node : Ir.node -> shell
val analyze : shell -> string -> summary
val analyze_node : Ir.node -> summary
