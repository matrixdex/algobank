(** * Algobank v0.1: Merkle soundness

    Proves that an unchanged Merkle hash means unchanged code underneath:
    if a node has the same Merkle hash in two analyses, every node it can
    reach in the first has a counterpart reachable from it in the second
    with the same Merkle hash, the same own hash, and the same pins
    ([merkle_sound], [merkle_sound_content]).

    The proof does not model Tarjan's algorithm. It applies to any
    back-end output that satisfies the conditions in [WF]; the function
    [check_backend] in [v0.1/pkgmerkle.py] checks exactly these
    conditions on every analysis and rejects outputs that fail them.

    Assumptions, stated as section hypotheses:
    - [H] returns 64 lowercase hex characters and is injective
      (collision resistance of SHA-256, idealized).
    - [srt] returns a permutation of its input (Python's [sorted]).

    The Python source being modeled:
<<
    def comp_base(comp, own, merk):
        return H("|".join(sorted(own[q] for q in comp["members"])) + "#"
                 + "|".join(merk[d] for d in comp["ext"]) + "#"
                 + "|".join(H(p) for p in comp["pins"]))

    merk[q] = H(base + own[q])
>>
*)

From Coq Require Import List Ascii Lia Permutation.
Import ListNotations.

(** ** Strings *)

Definition hexdigits : list ascii :=
  ["0";"1";"2";"3";"4";"5";"6";"7";"8";"9";"a";"b";"c";"d";"e";"f"]%char.
Definition is_hex (c : ascii) : bool := existsb (Ascii.eqb c) hexdigits.
Definition BAR : ascii := "|"%char.
Definition HSH : ascii := "#"%char.

Definition Dg (d : list ascii) : Prop := length d = 64 /\ forallb is_hex d = true.

(** Python's ["|".join(l)]. *)
Fixpoint join (l : list (list ascii)) : list ascii :=
  match l with
  | [] => []
  | [x] => x
  | x :: t => x ++ BAR :: join t
  end.

Lemma join_one : forall x, join [x] = x.
Proof. reflexivity. Qed.

Lemma join_more : forall x y t, join (x :: y :: t) = x ++ BAR :: join (y :: t).
Proof. reflexivity. Qed.

Lemma app_same_len {A} (a b c d : list A) :
  length a = length c -> a ++ b = c ++ d -> a = c /\ b = d.
Proof.
  revert c. induction a as [|x a IH]; intros [|y c] Hl He; simpl in *; try discriminate.
  - auto.
  - injection He as Hxy He'. subst y.
    destruct (IH c (eq_add_S _ _ Hl) He') as [Hac Hbd]. subst. auto.
Qed.

Lemma Dg_head : forall d, Dg d -> exists c r, d = c :: r /\ is_hex c = true.
Proof.
  intros [|c r] [L Hx]; simpl in *; [discriminate |].
  exists c, r. split; [reflexivity |]. destruct (is_hex c); [reflexivity | discriminate].
Qed.

(** A joined list of digests followed by [#] starts with the first digest. *)
Lemma join_head : forall y u, exists z, join (y :: u) = y ++ z.
Proof.
  intros y [|v u].
  - exists []. rewrite app_nil_r. reflexivity.
  - exists (BAR :: join (v :: u)). reflexivity.
Qed.

Lemma hsh_not_digest : forall y u r1 r2, Dg y -> HSH :: r1 <> join (y :: u) ++ HSH :: r2.
Proof.
  intros y u r1 r2 Dy E. destruct (join_head y u) as [z Ez]. rewrite Ez in E.
  destruct (Dg_head y Dy) as [c [r [-> Hc]]]. simpl in E. injection E as Ec _.
  subst c. discriminate.
Qed.

Lemma join_inj : forall l1 l2 r1 r2, Forall Dg l1 -> Forall Dg l2 ->
  join l1 ++ HSH :: r1 = join l2 ++ HSH :: r2 -> l1 = l2 /\ r1 = r2.
Proof.
  induction l1 as [|x t IH]; intros l2 r1 r2 F1 F2 E.
  - destruct l2 as [|y u].
    + simpl in E. injection E as E. auto.
    + exfalso. exact (hsh_not_digest y u r1 r2 (Forall_inv F2) E).
  - destruct l2 as [|y u].
    + exfalso. exact (hsh_not_digest x t r2 r1 (Forall_inv F1) (eq_sym E)).
    + pose proof (Forall_inv F1) as [Lx _]. pose proof (Forall_inv F2) as [Ly _].
      destruct t as [|v t'], u as [|w u'].
      * rewrite !join_one in E. apply app_same_len in E; [| congruence].
        destruct E as [-> E]. injection E as E. auto.
      * rewrite join_one, join_more in E. rewrite <- app_assoc, <- app_comm_cons in E.
        apply app_same_len in E; [| congruence]. destruct E as [_ E]. discriminate.
      * rewrite join_one, join_more in E. rewrite <- app_assoc, <- app_comm_cons in E.
        apply app_same_len in E; [| congruence]. destruct E as [_ E]. discriminate.
      * rewrite !join_more in E. rewrite <- !app_assoc, <- !app_comm_cons in E.
        apply app_same_len in E; [| congruence]. destruct E as [-> E]. injection E as E.
        destruct (IH (w :: u') r1 r2 (Forall_inv_tail F1) (Forall_inv_tail F2) E) as [Et Er].
        rewrite Et. auto.
Qed.

Lemma join_inj_end : forall l1 l2, Forall Dg l1 -> Forall Dg l2 -> join l1 = join l2 -> l1 = l2.
Proof.
  intros l1 l2 F1 F2 E. apply (f_equal (fun z => z ++ [HSH])) in E.
  exact (proj1 (join_inj l1 l2 [] [] F1 F2 E)).
Qed.

(** The component hash input: owns, external Merkle hashes, hashed pins. *)
Definition enc (a b c : list (list ascii)) : list ascii := join a ++ HSH :: join b ++ HSH :: join c.

Lemma enc_inj : forall a1 b1 c1 a2 b2 c2,
  Forall Dg a1 -> Forall Dg b1 -> Forall Dg c1 -> Forall Dg a2 -> Forall Dg b2 -> Forall Dg c2 ->
  enc a1 b1 c1 = enc a2 b2 c2 -> a1 = a2 /\ b1 = b2 /\ c1 = c2.
Proof.
  unfold enc. intros a1 b1 c1 a2 b2 c2 Fa1 Fb1 Fc1 Fa2 Fb2 Fc2 E.
  destruct (join_inj a1 a2 _ _ Fa1 Fa2 E) as [Ea E1].
  destruct (join_inj b1 b2 _ _ Fb1 Fb2 E1) as [Eb E2].
  auto using join_inj_end.
Qed.

Section MerkleSound.

Variable H : list ascii -> list ascii.
Hypothesis H_len : forall s, length (H s) = 64.
Hypothesis H_hex : forall s, forallb is_hex (H s) = true.
Hypothesis H_inj : forall s t, H s = H t -> s = t.

Variable srt : list (list ascii) -> list (list ascii).
Hypothesis srt_perm : forall l, Permutation (srt l) l.

Lemma H_Dg : forall s, Dg (H s).
Proof. intro s. split; [apply H_len | apply H_hex]. Qed.

Lemma map_H_inj : forall l1 l2, map H l1 = map H l2 -> l1 = l2.
Proof.
  induction l1 as [|x t IH]; intros [|y u] E; simpl in E; try discriminate.
  - reflexivity.
  - injection E as Exy Etu. f_equal; [exact (H_inj _ _ Exy) | exact (IH u Etu)].
Qed.

(** ** One analysis: the back end's output *)

Variables N C : Type.

Record G := mkG {
  own : N -> list ascii;          (* hash of the node's normalized code *)
  edges : N -> list N;            (* the node's dependencies *)
  comp : N -> C;                  (* its component *)
  members : C -> list N;          (* nodes in a component *)
  ext : C -> list N;              (* dependencies outside the component, in hashing order *)
  pins : C -> list (list ascii);  (* pin strings of the component *)
  merk : N -> list ascii          (* Merkle hash *)
}.

Definition base (g : G) (c : C) : list ascii :=
  H (enc (srt (map (own g) (members g c))) (map (merk g) (ext g c)) (map H (pins g c))).

Inductive reach (g : G) : N -> N -> Prop :=
| r_refl : forall n, reach g n n
| r_step : forall n x y, In x (edges g n) -> reach g x y -> reach g n y.

Lemma reach_trans : forall g a b c, reach g a b -> reach g b c -> reach g a c.
Proof.
  intros g a b c R1. induction R1 as [n | n x y Hx R IH]; intro R2.
  - exact R2.
  - apply r_step with x; [exact Hx | exact (IH R2)].
Qed.

(** The conditions [check_backend] verifies, one field per check. *)
Record WF (g : G) : Prop := {
  wf_own : forall n, Dg (own g n);
  wf_merk : forall n, merk g n = H (base g (comp g n) ++ own g n);
  wf_mem : forall n, In n (members g (comp g n));
  wf_comp : forall c m, In m (members g c) -> comp g m = c;
  wf_edge : forall n x, In x (edges g n) ->
    In x (members g (comp g n)) \/ In x (ext g (comp g n));
  wf_scc : forall c m1 m2, In m1 (members g c) -> In m2 (members g c) -> reach g m1 m2;
  wf_ext : forall c x, In x (ext g c) -> exists m, In m (members g c) /\ In x (edges g m)
}.

Lemma merk_Dg : forall g n, WF g -> Dg (merk g n).
Proof. intros g n W. rewrite (wf_merk g W). apply H_Dg. Qed.

Lemma Forall_srt_own : forall g c, WF g -> Forall Dg (srt (map (own g) (members g c))).
Proof.
  intros g c W. rewrite Forall_forall. intros x Hx.
  apply (Permutation_in _ (srt_perm _)) in Hx. apply in_map_iff in Hx.
  destruct Hx as [n [<- _]]. apply (wf_own g W).
Qed.

Lemma Forall_map_merk : forall g l, WF g -> Forall Dg (map (merk g) l).
Proof.
  intros g l W. rewrite Forall_forall. intros x Hx. apply in_map_iff in Hx.
  destruct Hx as [n [<- _]]. exact (merk_Dg g n W).
Qed.

Lemma Forall_map_H : forall l, Forall Dg (map H l).
Proof.
  intro l. rewrite Forall_forall. intros x Hx. apply in_map_iff in Hx.
  destruct Hx as [s [<- _]]. apply H_Dg.
Qed.

(** ** One step *)

Lemma one_step : forall g1 g2 n1 n2, WF g1 -> WF g2 -> merk g1 n1 = merk g2 n2 ->
  own g1 n1 = own g2 n2 /\ base g1 (comp g1 n1) = base g2 (comp g2 n2).
Proof.
  intros g1 g2 n1 n2 W1 W2 E. rewrite (wf_merk g1 W1), (wf_merk g2 W2) in E.
  apply H_inj in E. apply app_same_len in E.
  - destruct E as [Eb Eo]. auto.
  - unfold base. rewrite !H_len. reflexivity.
Qed.

Lemma base_inj : forall g1 g2 c1 c2, WF g1 -> WF g2 -> base g1 c1 = base g2 c2 ->
  srt (map (own g1) (members g1 c1)) = srt (map (own g2) (members g2 c2)) /\
  map (merk g1) (ext g1 c1) = map (merk g2) (ext g2 c2) /\
  pins g1 c1 = pins g2 c2.
Proof.
  intros g1 g2 c1 c2 W1 W2 E. unfold base in E. apply H_inj in E.
  destruct (enc_inj _ _ _ _ _ _ (Forall_srt_own g1 c1 W1) (Forall_map_merk g1 _ W1)
              (Forall_map_H _) (Forall_srt_own g2 c2 W2) (Forall_map_merk g2 _ W2)
              (Forall_map_H _) E) as [Eo [Em Ep]].
  auto using map_H_inj.
Qed.

Lemma member_match : forall g1 g2 c1 c2, WF g1 -> WF g2 -> base g1 c1 = base g2 c2 ->
  forall m1, In m1 (members g1 c1) ->
  exists m2, In m2 (members g2 c2) /\ merk g1 m1 = merk g2 m2.
Proof.
  intros g1 g2 c1 c2 W1 W2 B m1 Hm1.
  destruct (base_inj g1 g2 c1 c2 W1 W2 B) as [S _].
  assert (Hin : In (own g1 m1) (map (own g2) (members g2 c2))).
  { apply (Permutation_in _ (srt_perm _)). rewrite <- S.
    apply (Permutation_in _ (Permutation_sym (srt_perm _))). apply in_map. exact Hm1. }
  apply in_map_iff in Hin. destruct Hin as [m2 [Eo Hm2]].
  exists m2. split; [exact Hm2 |].
  rewrite (wf_merk g1 W1), (wf_merk g2 W2), (wf_comp g1 W1 c1 m1 Hm1), (wf_comp g2 W2 c2 m2 Hm2).
  rewrite B, Eo. reflexivity.
Qed.

Lemma ext_match : forall g1 g2 c1 c2, WF g1 -> WF g2 -> base g1 c1 = base g2 c2 ->
  forall x1, In x1 (ext g1 c1) ->
  exists x2, In x2 (ext g2 c2) /\ merk g1 x1 = merk g2 x2.
Proof.
  intros g1 g2 c1 c2 W1 W2 B x1 Hx1.
  destruct (base_inj g1 g2 c1 c2 W1 W2 B) as [_ [Em _]].
  assert (Hin : In (merk g1 x1) (map (merk g2) (ext g2 c2))).
  { rewrite <- Em. apply in_map. exact Hx1. }
  apply in_map_iff in Hin. destruct Hin as [x2 [Ex Hx2]].
  exists x2. auto.
Qed.

(** ** Main results *)

Theorem merkle_sound : forall g1 g2, WF g1 -> WF g2 ->
  forall n1 r1, reach g1 n1 r1 ->
  forall n2, merk g1 n1 = merk g2 n2 ->
  exists r2, reach g2 n2 r2 /\ merk g1 r1 = merk g2 r2.
Proof.
  intros g1 g2 W1 W2 n1 r1 R. induction R as [n | n x y Hx Rxy IH]; intros n2 E.
  - exists n2. split; [apply r_refl | exact E].
  - destruct (one_step g1 g2 n n2 W1 W2 E) as [_ B].
    assert (Hn2 : In n2 (members g2 (comp g2 n2))) by apply (wf_mem g2 W2).
    destruct (wf_edge g1 W1 n x Hx) as [Hm | He].
    + destruct (member_match g1 g2 _ _ W1 W2 B x Hm) as [x2 [Hx2 E2]].
      destruct (IH x2 E2) as [r2 [R2 Er]].
      exists r2. split; [| exact Er].
      apply reach_trans with x2; [exact (wf_scc g2 W2 _ n2 x2 Hn2 Hx2) | exact R2].
    + destruct (ext_match g1 g2 _ _ W1 W2 B x He) as [x2 [Hx2 E2]].
      destruct (wf_ext g2 W2 _ x2 Hx2) as [m [Hm Hmx]].
      destruct (IH x2 E2) as [r2 [R2 Er]].
      exists r2. split; [| exact Er].
      apply reach_trans with m; [exact (wf_scc g2 W2 _ n2 m Hn2 Hm) |].
      apply r_step with x2; [exact Hmx | exact R2].
Qed.

Theorem merkle_sound_content : forall g1 g2, WF g1 -> WF g2 ->
  forall n1 n2, merk g1 n1 = merk g2 n2 ->
  forall r1, reach g1 n1 r1 ->
  exists r2, reach g2 n2 r2 /\ merk g1 r1 = merk g2 r2 /\
             own g1 r1 = own g2 r2 /\ pins g1 (comp g1 r1) = pins g2 (comp g2 r2).
Proof.
  intros g1 g2 W1 W2 n1 n2 E r1 R.
  destruct (merkle_sound g1 g2 W1 W2 n1 r1 R n2 E) as [r2 [R2 Er]].
  destruct (one_step g1 g2 r1 r2 W1 W2 Er) as [Eo B].
  destruct (base_inj g1 g2 _ _ W1 W2 B) as [_ [_ Ep]].
  exists r2. auto.
Qed.

(** The relation is symmetric: the same holds from the second analysis to the first. *)
Corollary merkle_sound_back : forall g1 g2, WF g1 -> WF g2 ->
  forall n1 n2, merk g1 n1 = merk g2 n2 ->
  forall r2, reach g2 n2 r2 ->
  exists r1, reach g1 n1 r1 /\ merk g1 r1 = merk g2 r2 /\ own g1 r1 = own g2 r2.
Proof.
  intros g1 g2 W1 W2 n1 n2 E r2 R.
  destruct (merkle_sound_content g2 g1 W2 W1 n2 n1 (eq_sym E) r2 R) as [r1 [R1 [Em [Eo _]]]].
  exists r1. auto.
Qed.

End MerkleSound.

Print Assumptions merkle_sound_content.
