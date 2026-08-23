type system = {
  temporary_file : prefix:string -> suffix:string -> string;
  write_file : string -> string -> (unit, string) result;
  read_file : string -> (string, string) result;
  remove_file : string -> unit;
  command : string -> int;
}

val invoke : system -> Helper_client.invoke
