(** Extracts the proven [code_root] to OCaml for the model check. *)
Require Import Algobank.CodeRoot.
From Coq Require Import Extraction ExtrOcamlBasic ExtrOcamlChar.
Extraction Language OCaml.
Extraction "coderoot.ml" code_root.
