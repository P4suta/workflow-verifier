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

let shell_name = function
  | Posix -> "posix"
  | Bash -> "bash"
  | PowerShell -> "powershell"
  | Cmd -> "cmd"
  | Python -> "python"
  | Unknown_shell name -> name

let command_source (node : Ir.node) =
  match List.assoc_opt "command" node.attributes with
  | Some value -> (
      match Abstract_value.constants value with
      | Some (first :: rest) ->
          List.fold_left
            (fun longest candidate ->
              if String.length candidate > String.length longest then candidate
              else longest)
            first rest
      | Some [] | None -> node.name)
  | None -> node.name

let shell_of_node (node : Ir.node) =
  match
    Option.bind
      (List.assoc_opt "shell" node.attributes)
      Abstract_value.constants
  with
  | Some (name :: _) -> (
      match String.lowercase_ascii name with
      | "sh" | "posix" -> Posix
      | "bash" -> Bash
      | "pwsh" | "powershell" -> PowerShell
      | "cmd" | "cmd.exe" -> Cmd
      | "python" | "python3" -> Python
      | other -> Unknown_shell other)
  | Some [] | None -> Bash

let tokenize source : token list =
  let tokens = ref []
  and buffer = Buffer.create 32
  and start = ref 0
  and quote = ref None
  and token_quoted = ref false
  and has_text = ref false
  and escaped = ref false in
  let add_character character =
    Buffer.add_char buffer character;
    has_text := true
  in
  let flush stop =
    if !has_text then
      tokens :=
        ({
           text = Buffer.contents buffer;
           quoted = !token_quoted;
           start = !start;
           stop;
         }
          : token)
        :: !tokens;
    Buffer.clear buffer;
    token_quoted := false;
    has_text := false
  in
  String.iteri
    (fun index character ->
      match !quote with
      | Some delimiter ->
          token_quoted := true;
          if !escaped then (
            add_character character;
            escaped := false)
          else if character = '\\' && delimiter = '"' then escaped := true
          else if character = delimiter then quote := None
          else add_character character
      | None -> (
          match character with
          | ('"' | '\'') as delimiter ->
              if not !has_text then start := index;
              token_quoted := true;
              quote := Some delimiter
          | ' ' | '\t' | '\r' | '\n' -> flush index
          | character ->
              if not !has_text then start := index;
              add_character character))
    source;
  flush (String.length source);
  List.rev !tokens

let contains_any source needles =
  List.exists (fun needle -> Util.contains ~needle source) needles

let network_command source =
  contains_any source
    [
      "curl ";
      "curl.exe";
      "docker login";
      "helm registry login";
      "wget ";
      "invoke-webrequest";
      "invoke-restmethod";
      "podman login";
      "requests.";
      "urllib.";
      "httpclient";
      "fetch(";
    ]

let secret_reference source =
  tokenize source
  |> List.exists (fun (token : token) ->
      let text = String.lowercase_ascii token.text in
      let secret_name =
        contains_any text
          [
            "secret";
            "token";
            "password";
            "passwd";
            "private_key";
            "private-key";
            "access_key";
            "access-key";
            "credential";
          ]
      and value_reference =
        String.contains text '$' || String.contains text '%'
        || String.contains text '!'
        || contains_any text [ "secrets."; "environ"; "getenv" ]
      in
      secret_name && value_reference)

let output_command source =
  contains_any source
    [ "echo "; "printf "; "write-output"; "console.log"; "print(" ]

let split_top_level separator source =
  let length = String.length source in
  let rec scan index start quote escaped depth parts =
    if index >= length then
      String.sub source start (length - start) :: parts |> List.rev
    else
      let character = source.[index] in
      match quote with
      | Some delimiter ->
          if escaped then scan (index + 1) start quote false depth parts
          else if character = '\\' && delimiter = '"' then
            scan (index + 1) start quote true depth parts
          else if character = delimiter then
            scan (index + 1) start None false depth parts
          else scan (index + 1) start quote false depth parts
      | None -> (
          if escaped then scan (index + 1) start None false depth parts
          else if character = '\\' then
            scan (index + 1) start None true depth parts
          else
            match character with
            | ('"' | '\'') as delimiter ->
                scan (index + 1) start (Some delimiter) false depth parts
            | '(' -> scan (index + 1) start None false (depth + 1) parts
            | ')' -> scan (index + 1) start None false (max 0 (depth - 1)) parts
            | _ -> (
                match if depth = 0 then separator source index else None with
                | Some width ->
                    let part = String.sub source start (index - start) in
                    scan (index + width) (index + width) None false depth
                      (part :: parts)
                | None -> scan (index + 1) start None false depth parts))
  in
  scan 0 0 None false 0 [] |> List.map String.trim
  |> List.filter (fun part -> part <> "")

let sequence_separator source index =
  let length = String.length source in
  match source.[index] with
  | ';' -> Some 1
  | '&' when index + 1 < length && source.[index + 1] = '&' -> Some 2
  | '|' when index + 1 < length && source.[index + 1] = '|' -> Some 2
  | _ -> None

let pipeline_separator source index =
  match source.[index] with
  | '|' -> Some 1
  | _ -> None

type output_destination =
  | Standard_output
  | Private_file
  | Unknown_output of Unknown.reason

type output_quote = Output_single | Output_double | Output_double_escape

let output_destination shell source =
  match shell with
  | Python -> Standard_output
  | Unknown_shell name ->
      if Util.contains ~needle:">" source then
        Unknown_output (Unknown.Unsupported_syntax ("shell " ^ name))
      else Standard_output
  | Posix | Bash | PowerShell | Cmd -> (
      let length = String.length source in
      let rec scan index quote depth redirects =
        if index >= length then List.rev redirects
        else
          let character = source.[index] in
          match quote with
          | Some Output_double_escape ->
              scan (index + 1) (Some Output_double) depth redirects
          | Some Output_double ->
              if character = '\\' then
                scan (index + 1) (Some Output_double_escape) depth redirects
              else if character = '"' then scan (index + 1) None depth redirects
              else scan (index + 1) quote depth redirects
          | Some Output_single ->
              if character = '\'' then scan (index + 1) None depth redirects
              else scan (index + 1) quote depth redirects
          | None -> (
              match character with
              | '"' -> scan (index + 1) (Some Output_double) depth redirects
              | '\'' -> scan (index + 1) (Some Output_single) depth redirects
              | '(' -> scan (index + 1) None (depth + 1) redirects
              | ')' -> scan (index + 1) None (max 0 (depth - 1)) redirects
              | '>' when depth = 0 ->
                  let previous =
                    if index = 0 then None else Some source.[index - 1]
                  and following =
                    if index + 1 >= length then None
                    else Some source.[index + 1]
                  in
                  let descriptor =
                    match previous with
                    | Some ('0' .. '9' | '&' | '>') -> true
                    | _ -> false
                  in
                  if descriptor || following = Some '=' then
                    scan (index + 1) None depth redirects
                  else
                    let after =
                      if following = Some '>' then index + 2 else index + 1
                    in
                    scan after None depth (after :: redirects)
              | _ -> scan (index + 1) None depth redirects)
      in
      match scan 0 None 0 [] with
      | [ after ] ->
          let target =
            String.sub source after (length - after) |> String.trim
          in
          let target =
            if String.length target >= 2 then
              let first = target.[0]
              and last = target.[String.length target - 1] in
              if (first = '"' || first = '\'') && last = first then
                String.sub target 1 (String.length target - 2)
              else target
            else target
          in
          let lower = String.lowercase_ascii target in
          if
            target = ""
            || List.mem lower
                 [ "/dev/stdout"; "/dev/stderr"; "con"; "conout$"; "prn" ]
            || Util.starts_with ~prefix:"/proc/self/fd/" lower
          then Standard_output
          else if
            String.exists
              (function
                | ' ' | '\t' | '\r' | '\n' | '&' -> true
                | _ -> false)
              target
          then
            Unknown_output
              (Unknown.Unsupported_syntax "compound shell output redirection")
          else if
            String.exists
              (function
                | '$' | '%' | '!' -> true
                | _ -> false)
              target
          then
            Unknown_output
              (Unknown.Dynamic_string "dynamic shell output redirection")
          else Private_file
      | [] -> Standard_output
      | _ :: _ :: _ ->
          Unknown_output
            (Unknown.Unsupported_syntax "multiple shell output redirections"))

let output_preserving_command source =
  contains_any source
    [ "base64"; "cat"; "jq"; "openssl enc"; "sed "; "tee"; "tr "; "xxd" ]

let group_observability shell group =
  let stages = split_top_level pipeline_separator group in
  match List.rev stages with
  | [] -> (false, false, [])
  | final_stage :: _ -> (
      let secret = List.exists secret_reference stages
      and producer =
        List.exists
          (fun stage -> secret_reference stage && output_command stage)
          stages
      in
      if not secret then (false, false, [])
      else
        let network = List.exists network_command stages in
        if (not producer) || network then (network, false, [])
        else
          match output_destination shell final_stage with
          | Private_file -> (network, false, [])
          | Unknown_output reason -> (network, false, [ reason ])
          | Standard_output ->
              let output =
                match stages with
                | [ _ ] -> true
                | _ -> output_preserving_command final_stage
              in
              if output then (network, true, [])
              else
                ( network,
                  false,
                  [
                    Unknown.Unsupported_syntax
                      "unresolved pipeline stdout behavior";
                  ] ))

let line_observability shell source =
  source |> String.lowercase_ascii |> String.split_on_char '\n'
  |> List.fold_left
       (fun (network, output, unknowns) line ->
         split_top_level sequence_separator line
         |> List.fold_left
              (fun (network, output, unknowns) group ->
                let group_network, group_output, group_unknowns =
                  group_observability shell group
                in
                ( network || group_network,
                  output || group_output,
                  group_unknowns @ unknowns ))
              (network, output, unknowns))
       (false, false, [])

let expansion_marker shell text =
  match shell with
  | Posix | Bash | PowerShell | Unknown_shell _ ->
      String.contains text '$' || String.contains text '`'
  | Cmd ->
      (String.contains text '%' || String.contains text '!')
      && String.length text > 1
  | Python -> false

let expansions shell (tokens : token list) : expansion list =
  tokens
  |> List.filter_map (fun (token : token) ->
      if expansion_marker shell token.text then
        Some
          {
            expansion_text = token.text;
            expansion_quoted = token.quoted;
            expansion_start = token.start;
            expansion_stop = token.stop;
          }
      else None)

let analyze shell source =
  let lower = String.lowercase_ascii source in
  let network = network_command lower
  and file_write =
    contains_any lower
      [ " > "; ">>"; "set-content"; "out-file"; "writealltext"; "open(" ]
  and repository_change =
    contains_any lower [ "git push"; "gh pr merge"; "gh release" ]
  and deployment =
    contains_any lower
      [
        "kubectl apply";
        "terraform apply";
        "az deployment";
        "aws cloudformation deploy";
      ]
  and workflow_change =
    contains_any lower
      [
        ".github/workflows";
        ".gitlab-ci.yml";
        "azure-pipelines";
        ".circleci/config";
      ]
    && contains_any lower [ " > "; ">>"; "set-content"; "writealltext" ]
  in
  let effects =
    [
      (Ir.Network_request, network);
      (Ir.File_write, file_write);
      (Ir.Repository_change, repository_change);
      (Ir.Deployment_change, deployment);
      (Ir.Workflow_change, workflow_change);
      (Ir.Command_execution, true);
    ]
    |> List.filter_map (fun (value, present) ->
        if present then Some value else None)
    |> Util.deduplicate_compare Stdlib.compare
  and capabilities =
    [
      (Ir.Shell, true);
      (Ir.Network, network);
      (Ir.Filesystem_write, file_write || workflow_change);
      (Ir.Repository_write, repository_change || workflow_change);
      (Ir.Deployment, deployment);
    ]
    |> List.filter_map (fun (value, present) ->
        if present then Some value else None)
    |> Util.deduplicate_compare Stdlib.compare
  in
  let shell_unknowns =
    match shell with
    | Unknown_shell name -> [ Unknown.Unsupported_syntax ("shell " ^ name) ]
    | _ -> []
  in
  let tokens : token list = tokenize source in
  let expansions = expansions shell tokens in
  let provider_substitution =
    contains_any source [ "${{"; "<<"; "$[" ]
    ||
    match shell with
    | PowerShell | Cmd -> Util.contains ~needle:"$(" source
    | Posix | Bash | Python | Unknown_shell _ -> false
  in
  let dynamic_python =
    shell = Python
    && contains_any lower [ "eval("; "exec("; "subprocess"; "os.system(" ]
  in
  let unsafe_interpolation =
    provider_substitution || dynamic_python
    || List.exists (fun expansion -> not expansion.expansion_quoted) expansions
  in
  let secret_to_network, secret_to_output, observability_unknowns =
    line_observability shell source
  in
  let unknowns =
    shell_unknowns @ observability_unknowns
    |> Util.deduplicate_compare Unknown.compare
  in
  {
    shell;
    tokens;
    capabilities;
    effects;
    unknowns;
    expansions;
    unsafe_interpolation;
    secret_to_network;
    secret_to_output;
  }

let analyze_node node = analyze (shell_of_node node) (command_source node)
