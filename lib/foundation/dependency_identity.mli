type classification = Local | Immutable | Mutable | Unknown

val classify_reference : string -> classification
val valid_content_digest : string -> bool
