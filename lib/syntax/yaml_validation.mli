type issue = { code : string; message : string; span : Span.t }

val validate : file:string -> string -> issue list
