type reason =
  | Unsupported_syntax of string
  | External_state of string
  | Unresolved_dependency of string
  | Recursive_call of string
  | Dynamic_string of string
  | Phase_unavailable of string
  | Missing_evidence of string
  | Resource_limit of string

let compare = Stdlib.compare

let kind_and_detail = function
  | Unsupported_syntax detail -> ("unsupported_syntax", detail)
  | External_state detail -> ("external_state", detail)
  | Unresolved_dependency detail -> ("unresolved_dependency", detail)
  | Recursive_call detail -> ("recursive_call", detail)
  | Dynamic_string detail -> ("dynamic_string", detail)
  | Phase_unavailable detail -> ("phase_unavailable", detail)
  | Missing_evidence detail -> ("missing_evidence", detail)
  | Resource_limit detail -> ("resource_limit", detail)

let to_string reason =
  let kind, detail = kind_and_detail reason in
  if detail = "" then kind else kind ^ ": " ^ detail

let to_json reason =
  let kind, detail = kind_and_detail reason in
  Json.Object [ ("detail", Json.String detail); ("kind", Json.String kind) ]
