_workflow_verifier() {
  local commands="check resolve explain graph diff fix policy sandbox doctor completion migrate version"
  COMPREPLY=( $(compgen -W "$commands" -- "${COMP_WORDS[COMP_CWORD]}") )
}
complete -F _workflow_verifier workflow-verifier
