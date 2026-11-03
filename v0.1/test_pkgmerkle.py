"""Regression tests for pkgmerkle.py. Run: python3.14 -I v0.1/test_pkgmerkle.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algobank.pkgmerkle import Package, DIGEST_LEN, H

def changed(a, b):
    return sorted(k for k in a.nodes if k in b.nodes and a.nodes[k]["merkle"] != b.nodes[k]["merkle"])

def test_full_digest():
    assert len(H("x")) == DIGEST_LEN == 64
    p = Package({"m.py": "def f():\n    return 1\n"})
    assert len(p.root()) == 64 and all(len(n["merkle"]) == 64 for n in p.nodes.values())

def test_module_constant():
    """G1: a function's hash covers the module-level values it reads."""
    a = Package({"m.py": "LIMIT = 10\n\ndef f(x):\n    return x < LIMIT\n"})
    b = Package({"m.py": "LIMIT = 1000\n\ndef f(x):\n    return x < LIMIT\n"})
    assert "m:f" in changed(a, b)

def test_constant_in_other_module():
    """A constant imported from another module of the package."""
    a = Package({"pkg/__init__.py": "", "pkg/config.py": "LIMIT = 10\n",
                 "pkg/check.py": "from .config import LIMIT\n\ndef f(x):\n    return x < LIMIT\n"})
    b = Package({"pkg/__init__.py": "", "pkg/config.py": "LIMIT = 1000\n",
                 "pkg/check.py": "from .config import LIMIT\n\ndef f(x):\n    return x < LIMIT\n"})
    assert "pkg.check:f" in changed(a, b)

def test_class_attribute():
    a = Package({"m.py": "class C:\n    k = 1\n    def f(self):\n        return self.k\n"})
    b = Package({"m.py": "class C:\n    k = 2\n    def f(self):\n        return self.k\n"})
    assert "m:C.f" in changed(a, b)

def test_global_writer():
    """A function that writes module state through `global` affects every reader."""
    a = Package({"m.py": "x = 0\n\ndef w():\n    global x\n    x = 1\n\ndef r():\n    return x\n"})
    b = Package({"m.py": "x = 0\n\ndef w():\n    global x\n    x = 2\n\ndef r():\n    return x\n"})
    assert "m:r" in changed(a, b)

def test_unrelated_body_edit():
    """Editing one function's body does not change a function that neither calls nor reads it."""
    a = Package({"m.py": "def f():\n    return 1\n\ndef g():\n    return 2\n"})
    b = Package({"m.py": "def f():\n    return 1\n\ndef g():\n    return 3\n"})
    assert changed(a, b) == ["m:g"]

def test_unrelated_constant_does_not_spread():
    """G14: a function depends only on the module-level names it reads."""
    a = Package({"m.py": "A = 1\nB = 2\n\ndef f():\n    return A\n"})
    b = Package({"m.py": "A = 1\nB = 3\n\ndef f():\n    return A\n"})
    assert "m:f" not in changed(a, b)

def test_unrelated_module_does_not_spread():
    """G14: changing one module's top-level code does not change functions in modules that import it
    but do not read the changed name."""
    cfg = "LIMIT = 10\nOTHER = {}\n"
    use = "from . import config\n\ndef f(x):\n    return x < config.LIMIT\n"
    a = Package({"pkg/__init__.py": "", "pkg/config.py": cfg, "pkg/use.py": use})
    b = Package({"pkg/__init__.py": "", "pkg/config.py": cfg.replace("{}", "{1: 2}"), "pkg/use.py": use})
    c = Package({"pkg/__init__.py": "", "pkg/config.py": cfg.replace("10", "20"), "pkg/use.py": use})
    assert "pkg.use:f" not in changed(a, b)
    assert "pkg.use:f" in changed(a, c)

def test_function_reference():
    """A function passed as a value, not called, is still a dependency."""
    src = "def helper(x):\n    return x + {n}\n\ndef g(xs):\n    return list(map(helper, xs))\n"
    assert "m:g" in changed(Package({"m.py": src.format(n=1)}), Package({"m.py": src.format(n=2)}))

def test_registry_mutation():
    """Module-level statements that change a name (REG["a"] = ...) belong to that name."""
    src = "REG = {{}}\nREG['a'] = {n}\n\ndef f():\n    return REG\n"
    assert "m:f" in changed(Package({"m.py": src.format(n=1)}), Package({"m.py": src.format(n=2)}))

def test_conditional_import():
    src = "try:\n    import json\nexcept ImportError:\n    json = {v}\n\ndef f(s):\n    return json.loads(s)\n"
    assert "m:f" in changed(Package({"m.py": src.format(v="None")}), Package({"m.py": src.format(v="0")}))

def test_star_import():
    use = "from .x import *\n\ndef f():\n    return LIMIT\n"
    a = Package({"pkg/__init__.py": "", "pkg/x.py": "LIMIT = 1\n", "pkg/use.py": use})
    b = Package({"pkg/__init__.py": "", "pkg/x.py": "LIMIT = 2\n", "pkg/use.py": use})
    assert "pkg.use:f" in changed(a, b)

# ---- receivers of method calls (G7): link by method name, never narrow

TWO = "class Text:\n    def append(self, x):\n        return {t}\n\nclass Other:\n    def append(self, x):\n        return {o}\n\n"

def with_classes(body, t=1, o=1):
    return Package({"m.py": TWO.format(t=t, o=o) + body})

def test_parameter_receiver_stays_conservative():
    body = "def f(t):\n    t.append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, o=2))

def test_annotation_is_not_trusted():
    """An annotation does not narrow the receiver: the caller may pass any object."""
    body = "def f(t: Text):\n    t.append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, o=2))

def test_rebinding_disqualifies():
    body = "def make():\n    return Other()\n\ndef f():\n    t = Text()\n    for t in [make()]:\n        pass\n    t.append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, o=2))

def test_rebound_class_name_disqualifies():
    body = "Text = Other\n\ndef f():\n    t = Text()\n    t.append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, o=2))

def test_self_call_includes_subclass_override():
    """A.run calls self.step(); B(A) overrides step, so A.run can run B.step."""
    src = "class A:\n    def run(self):\n        return self.step()\n    def step(self):\n        return 1\n\n" \
          "class B(A):\n    def step(self):\n        return {n}\n"
    assert "m:A.run" in changed(Package({"m.py": src.format(n=2)}), Package({"m.py": src.format(n=3)}))

def test_super_call():
    src = "class A:\n    def step(self):\n        return {n}\n\nclass B(A):\n    def step(self):\n        return super().step() + 1\n"
    assert "m:B.step" in changed(Package({"m.py": src.format(n=1)}), Package({"m.py": src.format(n=2)}))

def test_call_on_call_result():
    """A method called on the result of another call is linked by name."""
    body = "def get():\n    return Text()\n\ndef f():\n    return get().append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, t=2))

def test_unresolved_base_stays_conservative():
    src = "from somewhere import Base\n\nclass C(Base):\n    pass\n\nclass Other:\n    def append(self, x):\n        return {o}\n\n" \
          "def f():\n    c = C()\n    c.append(1)\n"
    assert "m:f" in changed(Package({"m.py": src.format(o=1)}), Package({"m.py": src.format(o=2)}))

# ---- getattr with a name from a fixed list ------------------------------------------------------------

NETWORK_GO = "import socket\n\nclass K:\n    def go(self):\n        socket.socket()\n\n"

def caps_of(src, node="m:f"):
    return Package({"m.py": NETWORK_GO + src}).nodes[node]["caps"]

def test_getattr_literal_is_a_call_by_name():
    """getattr(k, "go")() runs K.go: the node reaches its scope instead of nothing."""
    assert caps_of("def f(k):\n    return getattr(k, 'go')()\n") == {"network"}

def test_getattr_over_literal_tuple_resolves():
    assert caps_of("def f(k):\n    for n in ('go', 'stop'):\n        getattr(k, n)()\n") == {"network"}

def test_getattr_over_comprehension_and_slice_resolves():
    assert caps_of("def f(k):\n    return [getattr(k, n) for n in ('go', 'stop')[:1]]\n") == {"network"}

def test_getattr_over_slots_resolves():
    src = "class S:\n    __slots__ = ('go', 'x')\n\ndef f(obj):\n    return [getattr(obj, s) for s in obj.__slots__]\n"
    assert caps_of(src) == {"network"}

def test_getattr_over_dataclass_fields_resolves():
    src = "from dataclasses import dataclass\n\n@dataclass\nclass D:\n    go: int\n\n" \
          "def f(inst):\n    return {k: getattr(inst, k) for k in inst.__dataclass_fields__}\n"
    assert caps_of(src) == {"network"}

def test_getattr_over_class_tuple_resolves():
    src = "class C:\n    _fields = ('go',)\n    def f(self):\n        return [getattr(self, x) for x in self._fields]\n"
    assert caps_of(src, "m:C.f") == {"network"}

def test_getattr_name_from_parameter_stays_top():
    assert "TOP" in caps_of("def f(k, name):\n    return getattr(k, name)\n")

def test_getattr_loop_name_rebound_stays_top():
    assert "TOP" in caps_of("def f(k, x):\n    for n in ('a',):\n        n = x\n        getattr(k, n)\n")

def test_getattr_list_changed_in_place_stays_top():
    assert "TOP" in caps_of("def f(k, x):\n    names = ['a']\n    names.append(x)\n    for n in names:\n        getattr(k, n)\n")
    assert "TOP" in caps_of("def f(k, x):\n    names = ['a']\n    names[0] = x\n    for n in names:\n        getattr(k, n)\n")

def test_getattr_over_computed_collection_stays_top():
    assert "TOP" in caps_of("def f(k, xs):\n    for n in tuple(xs):\n        getattr(k, n)\n")

def test_class_list_written_elsewhere_stays_top():
    src = "class C:\n    _fields = ('a',)\n    def f(self):\n        return [getattr(self, x) for x in self._fields]\n" \
          "def g(c, v):\n    c._fields = v\n"
    assert "TOP" in caps_of(src, "m:C.f")

def test_computed_write_on_unknown_object_blocks_lists():
    src = "class C:\n    _fields = ('a',)\n    def f(self):\n        return [getattr(self, x) for x in self._fields]\n" \
          "def g(obj, k, v):\n    setattr(obj, k, v)\n"
    assert "TOP" in caps_of(src, "m:C.f")

def test_computed_write_through_class_blocks_its_family():
    src = "class C:\n    _fields = ('a',)\n    def f(self):\n        return [getattr(self, x) for x in self._fields]\n" \
          "    @classmethod\n    def set(cls, k, v):\n        setattr(cls, k, v)\n"
    assert "TOP" in caps_of(src, "m:C.f")

def test_computed_instance_write_with_dict_blocks_its_family():
    """An instance with a __dict__ can shadow the class's list."""
    src = "class C:\n    _fields = ('a',)\n    def f(self):\n        return [getattr(self, x) for x in self._fields]\n" \
          "    def set(self, k, v):\n        setattr(self, k, v)\n"
    assert "TOP" in caps_of(src, "m:C.f")

def test_computed_instance_write_on_slotted_class_keeps_lists():
    """A fully slotted instance has no __dict__: a write by any name cannot replace a class attribute."""
    src = "class C:\n    __slots__ = ('go',)\n    _fields = ('go',)\n    def f(self):\n        return [getattr(self, x) for x in self._fields]\n" \
          "    def set(self, k, v):\n        super().__setattr__(k, v)\n"
    assert caps_of(src, "m:C.f") == {"network"}

def test_computed_instance_write_in_unrelated_class_keeps_lists():
    src = "class C:\n    _fields = ('go',)\n    def f(self):\n        return [getattr(self, x) for x in self._fields]\n" \
          "class Other:\n    def set(self, k, v):\n        self.__setattr__(k, v)\n"
    assert caps_of(src, "m:C.f") == {"network"}

def test_getattr_name_changes_the_hash():
    """The resolved names are edges, so a change to K.go changes f's Merkle hash."""
    src = "def f(k):\n    for n in ('go',):\n        getattr(k, n)()\n"
    a = Package({"m.py": NETWORK_GO + src})
    b = Package({"m.py": NETWORK_GO.replace("socket.socket()", "socket.socket(2)") + src})
    assert "m:f" in changed(a, b)

# ---- implicit calls: the audit -----------------------------------------------------------------------
# Python runs code that no call in the source names. Each case links f() to a socket only implicitly.
# SEEN must reach the socket. KNOWN_GAPS are the cases Algobank misses today: the test fails when one of them
# changes, so a fix (or a regression) is noticed and the list is updated on purpose.

NET = "        socket.socket()\n"
def dunder(name, args="self", ret="return self"):
    return f"class K:\n    def {name}({args}):\n{NET}        {ret}\n"

IMPLICIT = {
    "explicit method call": dunder("go") + "def f(k):\n    return k.go()\n",
    "K() runs __init__": dunder("__init__", ret="return None") + "def f():\n    return K()\n",
    "raise E() runs __init__": "class E(Exception):\n    def __init__(self):\n" + NET + "def f():\n    raise E()\n",
    "default argument at def time": "def g():\n" + NET[4:] + "def f():\n    def h(x=g()):\n        pass\n",
    "a + b": dunder("__add__", "self, o") + "def f(a, b):\n    return a + b\n",
    "a == b": dunder("__eq__", "self, o", "return True") + "def f(a, b):\n    return a == b\n",
    "a < b": dunder("__lt__", "self, o", "return True") + "def f(a, b):\n    return a < b\n",
    "-a": dunder("__neg__") + "def f(a):\n    return -a\n",
    "a[k]": dunder("__getitem__", "self, k") + "def f(a):\n    return a[0]\n",
    "a[k] = v": dunder("__setitem__", "self, k, v", "return None") + "def f(a):\n    a[0] = 1\n",
    "x in a": dunder("__contains__", "self, x", "return True") + "def f(a):\n    return 1 in a\n",
    "for x in a": dunder("__iter__", ret="return iter(())") + "def f(a):\n    for x in a:\n        pass\n",
    "with a": dunder("__enter__") + "    def __exit__(self, *e):\n        return False\ndef f(a):\n    with a:\n        pass\n",
    "if a": dunder("__bool__", ret="return True") + "def f(a):\n    if a:\n        return 1\n",
    "len(a)": dunder("__len__", ret="return 0") + "def f(a):\n    return len(a)\n",
    "str(a)": dunder("__str__", ret="return ''") + "def f(a):\n    return str(a)\n",
    "f-string": dunder("__format__", "self, spec", "return ''") + "def f(a):\n    return f'{a}'\n",
    "dict key (__hash__)": dunder("__hash__", ret="return 0") + "def f(a):\n    return {a: 1}\n",
    "a()": dunder("__call__") + "def f(a):\n    return a()\n",
    "await a": dunder("__await__", ret="return iter(())") + "async def f(a):\n    await a\n",
    "del a.x": dunder("__delattr__", "self, n", "return None") + "def f(a):\n    del a.x\n",
    "del a (__del__)": dunder("__del__", ret="return None") + "def f(a):\n    del a\n",
    "property": "class K:\n    @property\n    def p(self):\n" + NET + "        return 1\ndef f(a):\n    return a.p\n",
    "__getattr__": dunder("__getattr__", "self, n", "return 1") + "def f(a):\n    return a.missing\n",
    "__getattribute__": dunder("__getattribute__", "self, n", "return 1") + "def f(a):\n    return a.x\n",
    "__setattr__": dunder("__setattr__", "self, n, v", "return None") + "def f(a):\n    a.x = 1\n",
    "descriptor __get__": "class D:\n    def __get__(self, o, t=None):\n" + NET + "        return 1\nclass K:\n    d = D()\ndef f(a):\n    return a.d\n",
    "K() runs __new__": dunder("__new__", "c", "return object.__new__(c)") + "def f():\n    return K()\n",
    "K() runs metaclass __call__": "class M(type):\n    def __call__(c, *a):\n" + NET + "        return 1\nclass K(metaclass=M):\n    pass\ndef f():\n    return K()\n",
    "class statement runs __init_subclass__": "class K:\n    @classmethod\n    def __init_subclass__(c):\n" + NET + "def f():\n    class S(K):\n        pass\n",
    "class statement runs metaclass __new__": "class M(type):\n    def __new__(m, n, b, d):\n" + NET + "        return type.__new__(m, n, b, d)\ndef f():\n    class S(metaclass=M):\n        pass\n",
    "class statement runs __set_name__": "class D:\n    def __set_name__(self, o, n):\n" + NET + "def f():\n    class S:\n        d = D()\n",
    "class decorator": "def deco(c):\n" + NET[4:] + "    return c\ndef f():\n    @deco\n    class S:\n        pass\n",
    "function decorator": "def deco(fn):\n" + NET[4:] + "    return fn\ndef f():\n    @deco\n    def h():\n        pass\n",
    "decorated function runs the wrapper": "def deco(fn):\n    def wrapper(*a):\n" + NET + "        return fn(*a)\n    return wrapper\n"
                                           "@deco\ndef h():\n    return 1\ndef f():\n    return h()\n",
    "callback passed as an argument": "def g():\n" + NET[4:] + "def run(cb):\n    return cb()\ndef f():\n    return run(g)\n",
    "class attribute set to a function": "def g(self):\n" + NET[4:] + "class K:\n    go = g\ndef f(k):\n    return k.go()\n",
}
IMPLICIT_FILES = {"import inside a function": {"m.py": "def f():\n    import side\n", "side.py": "import socket\nsocket.socket()\n"}}

KNOWN_GAPS = {
    "a + b", "a == b", "a < b", "-a", "a[k]", "a[k] = v", "x in a", "for x in a", "with a", "if a", "len(a)", "str(a)",
    "f-string", "dict key (__hash__)", "a()", "await a", "del a.x", "del a (__del__)", "property", "__getattr__",
    "__getattribute__", "__setattr__", "descriptor __get__", "K() runs __new__", "K() runs metaclass __call__",
    "class statement runs __init_subclass__", "class statement runs metaclass __new__", "class statement runs __set_name__",
    "class decorator", "function decorator", "decorated function runs the wrapper", "callback passed as an argument",
    "class attribute set to a function", "import inside a function",
}

def test_implicit_calls():
    seen = set()
    cases = {k: {"m.py": "import socket\n" + v} for k, v in IMPLICIT.items()} | IMPLICIT_FILES
    for name, files in cases.items():
        p = Package(files)
        assert any("network" in n["direct_caps"] for n in p.nodes.values()), name      # the socket call itself is seen
        caps = p.nodes["m:f"]["caps"]
        if "network" in caps or "TOP" in caps: seen.add(name)
    assert set(cases) - seen == KNOWN_GAPS, sorted((set(cases) - seen) ^ KNOWN_GAPS)

def test_prefixes():
    """Leaves and interior nodes use different prefixes."""
    p = Package({"m.py": "def f():\n    return 1\n"})
    leaf = H("\x00" + "m:f=" + p.nodes["m:f"]["merkle"])
    assert leaf in p.leaves()

# ---- check_backend must reject every output that breaks a condition of the Merkle soundness proof

import copy
from algobank.pkgmerkle import backend, check_backend, comp_base

# Two modules, a mutual recursion (a component with two members), and a cross-module call.
CYCLE = {"pkg/__init__.py": "",
         "pkg/a.py": "from .b import g\n\ndef f(n):\n    return g(n - 1) if n else 0\n",
         "pkg/b.py": "def g(n):\n    from .a import f\n    return f(n) + 1\n\ndef h():\n    return g(3)\n"}

def rejected(facts, out, comps):
    """The checker's failure message, or None if it accepts."""
    try:
        check_backend(facts, out, comps)
    except ValueError as e:
        return str(e)
    return None

def rehash(facts, out, comps):
    """Recompute every Merkle hash from the (possibly altered) components, so the Merkle
    equation holds and only the structural condition under test can fail."""
    own = {k: v["own"] for k, v in facts.items()}
    merk = {}
    for c in comps:
        base = comp_base(c, own, merk)
        for q in c["members"]:
            merk[q] = H(base + own[q])
    for k in out:
        out[k]["merkle"] = merk[k]

def test_checker_accepts_real_output():
    p = Package(CYCLE)
    assert any(len(c["members"]) > 1 for c in p.comps)
    out, comps = backend(p.facts)
    assert not rejected(p.facts, out, comps)

def mutated(change, rehash_after=False):
    p = Package(CYCLE)
    out, comps = backend(p.facts)
    out, comps = copy.deepcopy(out), copy.deepcopy(comps)
    change(p.facts, out, comps)
    if rehash_after:
        rehash(p.facts, out, comps)
    return rejected(p.facts, out, comps) or ""

def test_checker_rejects_wrong_merkle():                      # wf_merk
    def change(facts, out, comps):
        k = next(iter(out)); out[k]["merkle"] = H("forged")
    assert "Merkle hash of" in mutated(change)

def test_checker_rejects_wrong_component():                   # wf_mem, wf_comp
    def change(facts, out, comps):
        k = next(iter(out)); out[k]["comp"] = (out[k]["comp"] + 1) % len(comps)
    assert "is not assigned to component" in mutated(change)

def test_checker_rejects_missing_external():                  # wf_edge
    def change(facts, out, comps):
        c = next(c for c in comps if c["ext"]); c["ext"] = c["ext"][1:]
    assert "is not covered" in mutated(change, rehash_after=True)

def test_checker_rejects_unused_external():                   # wf_ext
    def change(facts, out, comps):
        i = next(i for i, c in enumerate(comps) if i > 0)   # an earlier component exists to point at
        earlier = comps[0]["members"][0]
        if earlier not in comps[i]["ext"]:
            comps[i]["ext"] = sorted(comps[i]["ext"] + [earlier])
        else:
            raise AssertionError("pick another component")
    assert "is unused" in mutated(change, rehash_after=True)

def test_checker_rejects_own_not_digest():                    # wf_own
    def change(facts, out, comps):
        k = next(iter(facts)); facts[k]["own"] = "not a digest"
    assert "own hash of" in mutated(change)

def test_checker_rejects_unconnected_component():             # wf_scc
    """Two unrelated nodes in one component, with Merkle hashes computed consistently,
    so only the strong-connectivity condition can catch it."""
    facts = {n: dict(own=H(n), edges=set(), pins=set(), caps=set(), flags=set()) for n in ("x", "y")}
    comps = [dict(members=["x", "y"], ext=[], pins=[])]
    own = {n: facts[n]["own"] for n in facts}
    base = comp_base(comps[0], own, {})
    out = {n: dict(merkle=H(base + own[n]), caps=set(), flags=set(), comp=0) for n in facts}
    assert "not strongly connected" in rejected(facts, out, comps)

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} tests passed")
