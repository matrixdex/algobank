(** * Algobank v0.1: proof of the code root computation

    This file models [Package.root] from [v0.1/pkgmerkle.py] and proves:

    - [code_root_binding]: two packages with the same code root have the
      same set of (node id, Merkle hash) pairs.
    - [code_root_canonical]: the code root does not depend on the order
      in which nodes are listed.
    - [code_root_correct]: together, the code root is equal exactly when
      the sets of pairs are equal.

    Assumptions, stated as section hypotheses:
    - [H] returns 12 characters (as [hexdigest()[:12]] does) and is
      injective. Injectivity idealizes collision resistance.
    - [srt] returns a permutation of its input, and the same output for
      inputs that are permutations of each other (Python's [sorted] on
      strings).

    The Python source being modeled:
<<
    def leaves(self):
        return sorted(H(f"\x00{nid}={n['merkle']}") for nid, n in self.nodes.items())

    def root(self):
        level = self.leaves() or [H("empty")]
        while len(level) > 1:
            if len(level) % 2: level = level + [level[-1]]
            level = [H("\x01" + level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        return level[0]
>>
*)

From Coq Require Import List Ascii Lia Permutation Recdef.
Import ListNotations.

(** ** Characters and strings *)

(** Domain separation prefixes: 0x00 for leaf inputs, 0x01 for interior inputs. *)
Definition P0 : ascii := Ascii false false false false false false false false.
Definition P1 : ascii := Ascii true false false false false false false false.
Definition EQ : ascii := "="%char.
Definition empty_s : list ascii := ["e";"m";"p";"t";"y"]%char.

Lemma app_same_len {A} (a b c d : list A) :
  length a = length c -> a ++ b = c ++ d -> a = c /\ b = d.
Proof.
  revert c. induction a as [|x a IH]; intros [|y c] Hl He; simpl in *; try discriminate.
  - auto.
  - injection He as Hxy He'. subst y.
    destruct (IH c (eq_add_S _ _ Hl) He') as [Hac Hbd]. subst. auto.
Qed.

(** Induction two elements at a time, following the pairing in [root]. *)
Lemma list_ind2 {A} (P : list A -> Prop) :
  P [] -> (forall a, P [a]) -> (forall a b t, P t -> P (a :: b :: t)) ->
  forall l, P l.
Proof.
  intros H0 H1 H2. fix IH 1. intros [|a [|b t]].
  - exact H0.
  - apply H1.
  - apply H2. apply IH.
Qed.

Section CodeRoot.

(** ** Hash function *)

Variable H : list ascii -> list ascii.
Hypothesis H_len : forall s, length (H s) = 12.
Hypothesis H_inj : forall s t, H s = H t -> s = t.

(** A digest: any output of [H]. *)
Definition Dg (d : list ascii) : Prop := length d = 12.

Lemma H_Dg : forall s, Dg (H s).
Proof. apply H_len. Qed.

(** [leaf nid m] is [H(f"\x00{nid}={m}")]; [node a b] is [H("\x01" + a + b)]. *)
Definition leaf (nid m : list ascii) : list ascii := H (P0 :: nid ++ EQ :: m).
Definition node (a b : list ascii) : list ascii := H (P1 :: a ++ b).

(** The prefixes alone separate leaves from interior nodes. *)
Lemma leaf_ne_node : forall nid m a b, leaf nid m <> node a b.
Proof.
  unfold leaf, node. intros nid m a b E. apply H_inj in E. discriminate.
Qed.

Lemma node_inj : forall a b c d, Dg a -> Dg c -> node a b = node c d -> a = c /\ b = d.
Proof.
  unfold node, Dg. intros a b c d La Lc E. apply H_inj in E. injection E as E.
  apply app_same_len; [congruence | exact E].
Qed.

Lemma leaf_inj : forall n1 m1 n2 m2, length m1 = 12 -> length m2 = 12 ->
  leaf n1 m1 = leaf n2 m2 -> n1 = n2 /\ m1 = m2.
Proof.
  unfold leaf. intros n1 m1 n2 m2 L1 L2 E. apply H_inj in E. injection E as E.
  apply (f_equal (@rev ascii)) in E. rewrite !rev_app_distr in E. simpl in E.
  apply app_same_len in E.
  - destruct E as [E1 E2]. apply app_inj_tail in E1. destruct E1 as [E1 _].
    split.
    + rewrite <- (rev_involutive n1), <- (rev_involutive n2). congruence.
    + rewrite <- (rev_involutive m1), <- (rev_involutive m2). congruence.
  - rewrite !app_length, !rev_length. simpl. lia.
Qed.

(** ** The computation *)

(** One loop iteration: pair neighbours, pairing an odd last element with itself. *)
Fixpoint pairUp (l : list (list ascii)) : list (list ascii) :=
  match l with
  | [] => []
  | [a] => [node a a]
  | a :: b :: t => node a b :: pairUp t
  end.

Lemma pairUp_le : forall l, length (pairUp l) <= length l.
Proof. intro l. induction l as [|a|a b t IH] using list_ind2; simpl; lia. Qed.

(** The [while] loop, including [or [H("empty")]] for an empty package. *)
Function red (l : list (list ascii)) {measure length l} : list ascii :=
  match l with
  | [] => H empty_s
  | [a] => a
  | a :: b :: t => red (pairUp (a :: b :: t))
  end.
Proof.
  intros. simpl.
  match goal with |- context [pairUp ?x] => pose proof (pairUp_le x) end.
  lia.
Defined.

Lemma red_nil : red [] = H empty_s.
Proof. rewrite red_equation. reflexivity. Qed.

Lemma red_one : forall a, red [a] = a.
Proof. intro a. rewrite red_equation. reflexivity. Qed.

Lemma red_more : forall a b t, red (a :: b :: t) = red (pairUp (a :: b :: t)).
Proof. intros a b t. rewrite red_equation. reflexivity. Qed.

(** ** Heights: leaves are height 0, a node over two height-h values is h+1 *)

Inductive Ht : nat -> list ascii -> Prop :=
| Ht0 : forall nid m, length m = 12 -> Ht 0 (leaf nid m)
| HtS : forall h a b, Ht h a -> Ht h b -> Ht (S h) (node a b).

Lemma Ht_Dg : forall h d, Ht h d -> Dg d.
Proof. intros h d Hd. destruct Hd; apply H_Dg. Qed.

Lemma Forall_Ht_Dg : forall h l, Forall (Ht h) l -> Forall Dg l.
Proof.
  intros h l F. rewrite Forall_forall in *. intros x Hx. exact (Ht_Dg h x (F x Hx)).
Qed.

Lemma Ht_cases : forall h d, Ht h d ->
  (h = 0 /\ exists nid m, length m = 12 /\ d = leaf nid m) \/
  (exists h0 a b, h = S h0 /\ Ht h0 a /\ Ht h0 b /\ d = node a b).
Proof.
  intros h d Hd. destruct Hd as [nid m Lm | h a b Ha Hb].
  - left. split; [reflexivity | exists nid, m; auto].
  - right. exists h, a, b. auto.
Qed.

Lemma Ht_unique : forall h d, Ht h d -> forall h', Ht h' d -> h = h'.
Proof.
  intros h d Hd. induction Hd as [nid m Lm | h a b Ha IHa Hb IHb]; intros h' H'.
  - apply Ht_cases in H'.
    destruct H' as [[-> _] | [h0 [a [b [-> [Ha [Hb E]]]]]]].
    + reflexivity.
    + exfalso. exact (leaf_ne_node nid m a b E).
  - apply Ht_cases in H'.
    destruct H' as [[-> [nid [m [_ E]]]] | [h0 [a' [b' [-> [Ha' [Hb' E]]]]]]].
    + exfalso. exact (leaf_ne_node nid m a b (eq_sym E)).
    + destruct (node_inj a b a' b' (Ht_Dg _ _ Ha) (Ht_Dg _ _ Ha') E) as [Eaa _].
      subst a'. f_equal. apply IHa. exact Ha'.
Qed.

Lemma empty_not_Ht : forall g, ~ Ht g (H empty_s).
Proof.
  intros g Hg. apply Ht_cases in Hg.
  destruct Hg as [[_ [nid [m [_ E]]]] | [h0 [a [b [_ [_ [_ E]]]]]]].
  - unfold leaf in E. apply H_inj in E. discriminate.
  - unfold node in E. apply H_inj in E. discriminate.
Qed.

(** ** Properties of one level *)

Lemma pairUp_Ht : forall h l, Forall (Ht h) l -> Forall (Ht (S h)) (pairUp l).
Proof.
  intros h l. induction l as [|a|a b t IH] using list_ind2; intro F; simpl.
  - constructor.
  - constructor; [apply HtS; exact (Forall_inv F) | constructor].
  - constructor.
    + apply HtS; [exact (Forall_inv F) | exact (Forall_inv (Forall_inv_tail F))].
    + apply IH. exact (Forall_inv_tail (Forall_inv_tail F)).
Qed.

Lemma pairUp_mem : forall l z, In z (pairUp l) -> exists x y, In x l /\ z = node x y.
Proof.
  intro l. induction l as [|a|a b t IH] using list_ind2; intros z Hz; simpl in Hz.
  - contradiction.
  - destruct Hz as [<- | []]. exists a, a. split; [left; reflexivity | reflexivity].
  - destruct Hz as [<- | Hz].
    + exists a, b. split; [left; reflexivity | reflexivity].
    + destruct (IH z Hz) as [x [y [Hx ->]]].
      exists x, y. split; [right; right; exact Hx | reflexivity].
Qed.

Lemma pairUp_nodup : forall l, Forall Dg l -> NoDup l -> NoDup (pairUp l).
Proof.
  intro l. induction l as [|a|a b t IH] using list_ind2; intros F N; simpl.
  - constructor.
  - constructor; [simpl; tauto | constructor].
  - apply NoDup_cons_iff in N as [Na N1]. apply NoDup_cons_iff in N1 as [_ Nt].
    constructor.
    + intro Hin. destruct (pairUp_mem t _ Hin) as [x [y [Hx E]]].
      assert (Dx : Dg x).
      { rewrite Forall_forall in F. apply F. right. right. exact Hx. }
      destruct (node_inj a b x y (Forall_inv F) Dx E) as [Eax _]. subst x.
      apply Na. right. exact Hx.
    + apply IH; [exact (Forall_inv_tail (Forall_inv_tail F)) | exact Nt].
Qed.

(** Without [NoDup], [pairUp] is not injective: [a;b;c] and [a;b;c;c]
    collide (see [dup_collision]). Node ids are unique, so leaves are too. *)
Lemma pairUp_inj : forall l1 l2, Forall Dg l1 -> Forall Dg l2 -> NoDup l1 -> NoDup l2 ->
  pairUp l1 = pairUp l2 -> l1 = l2.
Proof.
  intro l1. induction l1 as [|a|a b t IH] using list_ind2;
  intros l2 F1 F2 N1 N2 E; destruct l2 as [|c [|d u]]; simpl in E; try discriminate.
  - reflexivity.
  - injection E as E.
    destruct (node_inj a a c c (Forall_inv F1) (Forall_inv F2) E) as [Eac _].
    subst c. reflexivity.
  - injection E as E Eu.
    destruct (node_inj a a c d (Forall_inv F1) (Forall_inv F2) E) as [Eac Ead].
    subst c d. exfalso. apply NoDup_cons_iff in N2 as [Na _]. apply Na. left. reflexivity.
  - injection E as E Et.
    destruct (node_inj a b c c (Forall_inv F1) (Forall_inv F2) E) as [Eac Ebc].
    subst a b. exfalso. apply NoDup_cons_iff in N1 as [Nc _]. apply Nc. left. reflexivity.
  - injection E as E Et.
    destruct (node_inj a b c d (Forall_inv F1) (Forall_inv F2) E) as [Eac Ebd].
    subst c d. f_equal. f_equal.
    apply NoDup_cons_iff in N1 as [_ N1]. apply NoDup_cons_iff in N1 as [_ N1].
    apply NoDup_cons_iff in N2 as [_ N2]. apply NoDup_cons_iff in N2 as [_ N2].
    apply IH; auto.
    + exact (Forall_inv_tail (Forall_inv_tail F1)).
    + exact (Forall_inv_tail (Forall_inv_tail F2)).
Qed.

Lemma dup_collision : forall a b c, red [a; b; c] = red [a; b; c; c].
Proof. intros a b c. rewrite (red_more a b [c]), (red_more a b [c; c]). reflexivity. Qed.

(** ** The loop *)

Lemma red_Ht : forall n l h, length l <= n -> l <> [] -> Forall (Ht h) l ->
  exists g, h <= g /\ Ht g (red l) /\ (2 <= length l -> h < g).
Proof.
  induction n as [|n IH]; intros l h Ln Ne F.
  - destruct l; [contradiction | simpl in Ln; lia].
  - destruct l as [|a [|b t]].
    + contradiction.
    + exists h. rewrite red_one.
      split; [lia | split; [exact (Forall_inv F) | simpl; lia]].
    + rewrite red_more.
      assert (Hp : length (pairUp (a :: b :: t)) <= n).
      { simpl. pose proof (pairUp_le t). simpl in Ln. lia. }
      assert (Hne : pairUp (a :: b :: t) <> []) by (simpl; discriminate).
      destruct (IH (pairUp (a :: b :: t)) (S h) Hp Hne (pairUp_Ht h _ F))
        as [g [Hg [Htg _]]].
      exists g. split; [lia | split; [exact Htg | intros; lia]].
Qed.

Theorem red_binding : forall n l1 l2 h,
  length l1 + length l2 <= n -> l1 <> [] -> l2 <> [] ->
  Forall (Ht h) l1 -> Forall (Ht h) l2 -> NoDup l1 -> NoDup l2 ->
  red l1 = red l2 -> l1 = l2.
Proof.
  induction n as [|n IH]; intros l1 l2 h Ln Ne1 Ne2 F1 F2 N1 N2 E.
  - destruct l1; [contradiction | simpl in Ln; lia].
  - destruct l1 as [|a [|b t]]; [contradiction | |];
    destruct l2 as [|c [|d u]]; try contradiction.
    + rewrite !red_one in E. subst. reflexivity.
    + exfalso. rewrite red_one in E.
      destruct (red_Ht _ (c :: d :: u) h (le_n _) Ne2 F2) as [g [_ [Hg Hlt]]].
      rewrite <- E in Hg.
      pose proof (Ht_unique h a (Forall_inv F1) g Hg). simpl in Hlt. lia.
    + exfalso. rewrite red_one in E.
      destruct (red_Ht _ (a :: b :: t) h (le_n _) Ne1 F1) as [g [_ [Hg Hlt]]].
      rewrite E in Hg.
      pose proof (Ht_unique h c (Forall_inv F2) g Hg). simpl in Hlt. lia.
    + rewrite (red_more a b t), (red_more c d u) in E.
      apply pairUp_inj.
      * exact (Forall_Ht_Dg h _ F1).
      * exact (Forall_Ht_Dg h _ F2).
      * exact N1.
      * exact N2.
      * apply (IH _ _ (S h)).
        -- simpl. pose proof (pairUp_le t). pose proof (pairUp_le u). simpl in Ln. lia.
        -- simpl. discriminate.
        -- simpl. discriminate.
        -- exact (pairUp_Ht h _ F1).
        -- exact (pairUp_Ht h _ F2).
        -- exact (pairUp_nodup _ (Forall_Ht_Dg h _ F1) N1).
        -- exact (pairUp_nodup _ (Forall_Ht_Dg h _ F2) N2).
        -- exact E.
Qed.

(** ** Packages *)

Variable srt : list (list ascii) -> list (list ascii).
Hypothesis srt_perm : forall l, Permutation (srt l) l.

(** A package is its list of (node id, Merkle hash) pairs. *)
Definition leafs (P : list (list ascii * list ascii)) : list (list ascii) :=
  map (fun p => leaf (fst p) (snd p)) P.

Definition code_root (P : list (list ascii * list ascii)) : list ascii :=
  red (srt (leafs P)).

(** Well formed: no repeated pair (node ids are dict keys), and every
    Merkle hash is a 12-character digest. *)
Definition WF (P : list (list ascii * list ascii)) : Prop :=
  NoDup P /\ Forall (fun p => length (snd p) = 12) P.

Lemma leafs_Ht : forall P, WF P -> Forall (Ht 0) (leafs P).
Proof.
  intros P [_ F]. unfold leafs. rewrite Forall_forall in *. intros x Hx.
  apply in_map_iff in Hx. destruct Hx as [p [<- Hp]]. apply Ht0. exact (F p Hp).
Qed.

Lemma leafs_nodup : forall P, WF P -> NoDup (leafs P).
Proof.
  intros P [N F]. unfold leafs. induction P as [|p P IH]; simpl.
  - constructor.
  - apply NoDup_cons_iff in N as [Np N].
    pose proof (Forall_inv F) as Lp. pose proof (Forall_inv_tail F) as FP.
    constructor.
    + intro Hin. apply in_map_iff in Hin. destruct Hin as [q [Eq Hq]].
      rewrite Forall_forall in FP.
      destruct (leaf_inj _ _ _ _ (FP q Hq) Lp Eq) as [E1 E2].
      apply Np. destruct p, q. simpl in *. subst. exact Hq.
    + apply IH; assumption.
Qed.

Lemma srt_Ht : forall P, WF P -> Forall (Ht 0) (srt (leafs P)).
Proof.
  intros P W. pose proof (leafs_Ht P W) as F. rewrite Forall_forall in *.
  intros x Hx. apply F. exact (Permutation_in _ (srt_perm _) Hx).
Qed.

Lemma srt_nodup : forall P, WF P -> NoDup (srt (leafs P)).
Proof.
  intros P W. exact (Permutation_NoDup (Permutation_sym (srt_perm _)) (leafs_nodup P W)).
Qed.

Lemma root_nonempty_ne_empty : forall P a l, WF P -> srt (leafs P) = a :: l ->
  red (a :: l) <> H empty_s.
Proof.
  intros P a l W S E.
  assert (F : Forall (Ht 0) (a :: l)) by (rewrite <- S; apply srt_Ht; exact W).
  destruct (red_Ht _ (a :: l) 0 (le_n _) ltac:(discriminate) F) as [g [_ [Hg _]]].
  rewrite E in Hg. exact (empty_not_Ht g Hg).
Qed.

Lemma same_sorted_leaves : forall P1 P2, WF P1 -> WF P2 ->
  code_root P1 = code_root P2 -> srt (leafs P1) = srt (leafs P2).
Proof.
  intros P1 P2 W1 W2 E. unfold code_root in E.
  destruct (srt (leafs P1)) as [|a1 l1] eqn:S1;
  destruct (srt (leafs P2)) as [|a2 l2] eqn:S2.
  - reflexivity.
  - rewrite red_nil in E. exfalso. exact (root_nonempty_ne_empty P2 a2 l2 W2 S2 (eq_sym E)).
  - rewrite red_nil in E. exfalso. exact (root_nonempty_ne_empty P1 a1 l1 W1 S1 E).
  - apply (red_binding (length (a1 :: l1) + length (a2 :: l2)) _ _ 0).
    + lia.
    + discriminate.
    + discriminate.
    + rewrite <- S1. apply srt_Ht. exact W1.
    + rewrite <- S2. apply srt_Ht. exact W2.
    + rewrite <- S1. apply srt_nodup. exact W1.
    + rewrite <- S2. apply srt_nodup. exact W2.
    + exact E.
Qed.

Lemma mem_transfer : forall P1 P2 x, WF P1 -> WF P2 ->
  srt (leafs P1) = srt (leafs P2) -> In x P1 -> In x P2.
Proof.
  intros P1 P2 x [N1 F1] [N2 F2] S Hx.
  assert (Lx : length (snd x) = 12) by (rewrite Forall_forall in F1; exact (F1 x Hx)).
  assert (Hin : In (leaf (fst x) (snd x)) (leafs P2)).
  { apply (Permutation_in _ (srt_perm _)). rewrite <- S.
    apply (Permutation_in _ (Permutation_sym (srt_perm _))).
    unfold leafs. apply in_map_iff. exists x. auto. }
  unfold leafs in Hin. apply in_map_iff in Hin. destruct Hin as [y [Ey Hy]].
  rewrite Forall_forall in F2.
  destruct (leaf_inj _ _ _ _ (F2 y Hy) Lx Ey) as [E1 E2].
  destruct x, y. simpl in *. subst. exact Hy.
Qed.

(** ** Main results *)

Theorem code_root_binding : forall P1 P2, WF P1 -> WF P2 ->
  code_root P1 = code_root P2 -> forall x, In x P1 <-> In x P2.
Proof.
  intros P1 P2 W1 W2 E x. pose proof (same_sorted_leaves P1 P2 W1 W2 E) as S.
  split; apply mem_transfer; auto.
Qed.

Theorem code_root_canonical :
  (forall l l', Permutation l l' -> srt l = srt l') ->
  forall P1 P2, Permutation P1 P2 -> code_root P1 = code_root P2.
Proof.
  intros C P1 P2 Pm. unfold code_root, leafs. f_equal. apply C. apply Permutation_map. exact Pm.
Qed.

Theorem code_root_correct :
  (forall l l', Permutation l l' -> srt l = srt l') ->
  forall P1 P2, WF P1 -> WF P2 ->
  (code_root P1 = code_root P2 <-> forall x, In x P1 <-> In x P2).
Proof.
  intros C P1 P2 W1 W2. split.
  - apply code_root_binding; assumption.
  - intro M. apply code_root_canonical; [exact C |].
    destruct W1 as [N1 _]. destruct W2 as [N2 _].
    apply NoDup_Permutation; assumption.
Qed.

End CodeRoot.

Print Assumptions code_root_correct.
