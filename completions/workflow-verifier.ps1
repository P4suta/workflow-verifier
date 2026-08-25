Register-ArgumentCompleter -Native -CommandName workflow-verifier -ScriptBlock {
  param($wordToComplete)
  'check','resolve','explain','graph','diff','fix','policy','sandbox','doctor','completion','migrate','version' |
    Where-Object { $_ -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}
