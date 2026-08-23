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
}

let shell_name = function
  | Posix -> "posix"
  | Bash -> "bash"
  | PowerShell -> "powershell"
  | Cmd -> "cmd"
  | Python -> "python"
  | Unknown_shell name -> name

let tokenize source : token list =
  let tokens = ref []
  and buffer = Buffer.create 32
  and start = ref 0
  and quote = ref None
  and token_quoted = ref false
  and escaped = ref false in
  let flush stop =
    if Buffer.length buffer > 0 then (
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
      token_quoted := false)
  in
  String.iteri
    (fun index character ->
      match !quote with
      | Some delimiter ->
          token_quoted := true;
          if !escaped then (
            Buffer.add_char buffer character;
            escaped := false)
          else if character = '\\' && delimiter = '"' then escaped := true
          else if character = delimiter then quote := None
          else Buffer.add_char buffer character
      | None -> (
          match character with
          | ('"' | '\'') as delimiter ->
              if Buffer.length buffer = 0 then start := index;
              token_quoted := true;
              quote := Some delimiter
          | ' ' | '\t' | '\r' | '\n' -> flush index
          | character ->
              if Buffer.length buffer = 0 then start := index;
              Buffer.add_char buffer character))
    source;
  flush (String.length source);
  List.rev !tokens

let contains_any source needles =
  List.exists (fun needle -> Util.contains ~needle source) needles

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
  let network =
    contains_any lower
      [
        "curl ";
        "curl.exe";
        "wget ";
        "invoke-webrequest";
        "invoke-restmethod";
        "requests.";
        "urllib.";
        "httpclient";
        "fetch(";
      ]
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
  let unknowns =
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
  {
    shell;
    tokens;
    capabilities;
    effects;
    unknowns;
    expansions;
    unsafe_interpolation;
  }
