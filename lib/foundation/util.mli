val ( let* ) :
  ('a, 'error) result -> ('a -> ('b, 'error) result) -> ('b, 'error) result

val ( let+ ) : ('a, 'error) result -> ('a -> 'b) -> ('b, 'error) result
val trim : string -> string
val starts_with : prefix:string -> string -> bool
val ends_with : suffix:string -> string -> bool
val contains : needle:string -> string -> bool
val split_once : char -> string -> string * string option
val list_filter_map : ('a -> 'b option) -> 'a list -> 'b list
val deduplicate_compare : ('a -> 'a -> int) -> 'a list -> 'a list
val deduplicate_strings : string list -> string list
val mkdir_p : string -> unit
val read_file : string -> (string, string) result
val write_file : string -> string -> (unit, string) result
val normalize_slashes : string -> string
val path_join : string -> string -> string
val extension_lower : string -> string
val files_recursively : string -> string list
val replace_all : needle:string -> replacement:string -> string -> string
val lowercase : string -> string
val option_value : default:'a -> 'a option -> 'a
val take : int -> 'a list -> 'a list
val take_while : ('a -> bool) -> 'a list -> 'a list
val string_of_file_error : string -> string -> string
