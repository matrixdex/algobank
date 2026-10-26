(* Reads one package per line ("nid merkle nid merkle ..."), prints its code root.
   H is the MD5 hex digest written twice (64 characters), the same stand-in the Python side uses. *)
let explode s = List.init (String.length s) (String.get s)
let implode l = String.of_seq (List.to_seq l)
let h cs = let d = Digest.to_hex (Digest.string (implode cs)) in explode (d ^ d)
let srt l = List.sort compare l

let rec pairs = function
  | n :: m :: rest -> (explode n, explode m) :: pairs rest
  | [] -> []
  | _ -> failwith "odd token count"

let () =
  try
    while true do
      let line = input_line stdin in
      let toks = List.filter (fun t -> t <> "") (String.split_on_char ' ' line) in
      print_endline (implode (Coderoot.code_root h srt (pairs toks)))
    done
  with End_of_file -> ()
