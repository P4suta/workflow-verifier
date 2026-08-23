val link :
  root:string ->
  sources:Frontend_intf.source_unit list ->
  Frontend_intf.compilation list ->
  (Frontend_intf.compilation list, Frontend_intf.problem list) result
