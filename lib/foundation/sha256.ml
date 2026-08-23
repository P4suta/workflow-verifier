(* A compact, allocation-conscious SHA-256 implementation using only Stdlib. *)

let constants =
  [|
    0x428a2f98l;
    0x71374491l;
    0xb5c0fbcfl;
    0xe9b5dba5l;
    0x3956c25bl;
    0x59f111f1l;
    0x923f82a4l;
    0xab1c5ed5l;
    0xd807aa98l;
    0x12835b01l;
    0x243185bel;
    0x550c7dc3l;
    0x72be5d74l;
    0x80deb1fel;
    0x9bdc06a7l;
    0xc19bf174l;
    0xe49b69c1l;
    0xefbe4786l;
    0x0fc19dc6l;
    0x240ca1ccl;
    0x2de92c6fl;
    0x4a7484aal;
    0x5cb0a9dcl;
    0x76f988dal;
    0x983e5152l;
    0xa831c66dl;
    0xb00327c8l;
    0xbf597fc7l;
    0xc6e00bf3l;
    0xd5a79147l;
    0x06ca6351l;
    0x14292967l;
    0x27b70a85l;
    0x2e1b2138l;
    0x4d2c6dfcl;
    0x53380d13l;
    0x650a7354l;
    0x766a0abbl;
    0x81c2c92el;
    0x92722c85l;
    0xa2bfe8a1l;
    0xa81a664bl;
    0xc24b8b70l;
    0xc76c51a3l;
    0xd192e819l;
    0xd6990624l;
    0xf40e3585l;
    0x106aa070l;
    0x19a4c116l;
    0x1e376c08l;
    0x2748774cl;
    0x34b0bcb5l;
    0x391c0cb3l;
    0x4ed8aa4al;
    0x5b9cca4fl;
    0x682e6ff3l;
    0x748f82eel;
    0x78a5636fl;
    0x84c87814l;
    0x8cc70208l;
    0x90befffal;
    0xa4506cebl;
    0xbef9a3f7l;
    0xc67178f2l;
  |]

let rotate_right value amount =
  Int32.logor
    (Int32.shift_right_logical value amount)
    (Int32.shift_left value (32 - amount))

let digest_bytes input =
  let input_length = Bytes.length input in
  let bit_length = Int64.mul (Int64.of_int input_length) 8L in
  let padding = (56 - ((input_length + 1) mod 64) + 64) mod 64 in
  let message = Bytes.make (input_length + 1 + padding + 8) '\000' in
  Bytes.blit input 0 message 0 input_length;
  Bytes.set message input_length '\x80';
  for index = 0 to 7 do
    let shift = 8 * (7 - index) in
    Bytes.set message
      (Bytes.length message - 8 + index)
      (Char.chr
         (Int64.to_int
            (Int64.logand (Int64.shift_right_logical bit_length shift) 0xffL)))
  done;
  let state =
    [|
      0x6a09e667l;
      0xbb67ae85l;
      0x3c6ef372l;
      0xa54ff53al;
      0x510e527fl;
      0x9b05688cl;
      0x1f83d9abl;
      0x5be0cd19l;
    |]
  in
  let schedule = Array.make 64 0l in
  let add4 a b c d = Int32.add (Int32.add a b) (Int32.add c d) in
  for block = 0 to (Bytes.length message / 64) - 1 do
    for word = 0 to 15 do
      let offset = (block * 64) + (word * 4) in
      let byte index =
        Int32.of_int (Char.code (Bytes.get message (offset + index)))
      in
      schedule.(word) <-
        Int32.logor
          (Int32.shift_left (byte 0) 24)
          (Int32.logor
             (Int32.shift_left (byte 1) 16)
             (Int32.logor (Int32.shift_left (byte 2) 8) (byte 3)))
    done;
    for word = 16 to 63 do
      let x = schedule.(word - 15) and y = schedule.(word - 2) in
      let sigma0 =
        Int32.logxor (rotate_right x 7)
          (Int32.logxor (rotate_right x 18) (Int32.shift_right_logical x 3))
      and sigma1 =
        Int32.logxor (rotate_right y 17)
          (Int32.logxor (rotate_right y 19) (Int32.shift_right_logical y 10))
      in
      schedule.(word) <-
        add4 schedule.(word - 16) sigma0 schedule.(word - 7) sigma1
    done;
    let a = ref state.(0)
    and b = ref state.(1)
    and c = ref state.(2)
    and d = ref state.(3)
    and e = ref state.(4)
    and f = ref state.(5)
    and g = ref state.(6)
    and h = ref state.(7) in
    for round = 0 to 63 do
      let sum1 =
        Int32.logxor (rotate_right !e 6)
          (Int32.logxor (rotate_right !e 11) (rotate_right !e 25))
      and choice =
        Int32.logxor (Int32.logand !e !f) (Int32.logand (Int32.lognot !e) !g)
      and sum0 =
        Int32.logxor (rotate_right !a 2)
          (Int32.logxor (rotate_right !a 13) (rotate_right !a 22))
      and majority =
        Int32.logxor (Int32.logand !a !b)
          (Int32.logxor (Int32.logand !a !c) (Int32.logand !b !c))
      in
      let temporary1 =
        add4 !h sum1 choice (Int32.add constants.(round) schedule.(round))
      and temporary2 = Int32.add sum0 majority in
      h := !g;
      g := !f;
      f := !e;
      e := Int32.add !d temporary1;
      d := !c;
      c := !b;
      b := !a;
      a := Int32.add temporary1 temporary2
    done;
    state.(0) <- Int32.add state.(0) !a;
    state.(1) <- Int32.add state.(1) !b;
    state.(2) <- Int32.add state.(2) !c;
    state.(3) <- Int32.add state.(3) !d;
    state.(4) <- Int32.add state.(4) !e;
    state.(5) <- Int32.add state.(5) !f;
    state.(6) <- Int32.add state.(6) !g;
    state.(7) <- Int32.add state.(7) !h
  done;
  let output = Bytes.create 32 in
  Array.iteri
    (fun index value ->
      for byte_index = 0 to 3 do
        let shift = 8 * (3 - byte_index) in
        Bytes.set output
          ((index * 4) + byte_index)
          (Char.chr
             (Int32.to_int
                (Int32.logand (Int32.shift_right_logical value shift) 0xffl)))
      done)
    state;
  output

let to_hex bytes =
  let alphabet = "0123456789abcdef" in
  let output = Bytes.create (Bytes.length bytes * 2) in
  Bytes.iteri
    (fun index character ->
      let value = Char.code character in
      Bytes.set output (index * 2) alphabet.[value lsr 4];
      Bytes.set output ((index * 2) + 1) alphabet.[value land 0xf])
    bytes;
  Bytes.unsafe_to_string output

let digest_string value = digest_bytes (Bytes.of_string value) |> to_hex

let digest_file path =
  match Util.read_file path with
  | Ok contents -> Ok (digest_string contents)
  | Error _ as error -> error
