// BANK SEARCH: "package" or "package v1.2.3" (also "package 1.2.3", "package==1.2.3"); ?q= in the address works too
(() => {
  const q = document.getElementById("q"), msg = document.getElementById("msg");
  const rows = [...document.querySelectorAll("#bank tbody tr")];
  const norm = s => s.toLowerCase().replace(/[-_.]+/g, "-");          // PEP 503 package names
  function search() {
    const [name = "", v = ""] = q.value.trim().split(/\s+|==/).filter(Boolean);
    const version = v.replace(/^v/i, "");
    const n = norm(name);
    const named = rows.filter(r => version ? norm(r.dataset.name) === n : norm(r.dataset.name).includes(n));
    const exact = named.filter(r => r.dataset.version === version);
    const shown = version && exact.length ? exact : named;
    rows.forEach(r => r.hidden = !shown.includes(r));
    msg.textContent = !name ? ""
      : version && !exact.length ? `${name} v${version} are not algobanked`
      : !named.length ? `${name} is not algobanked` : "";
    history.replaceState(null, "", name ? "?q=" + encodeURIComponent(q.value.trim()) : location.pathname);
  }
  q.value = new URLSearchParams(location.search).get("q") || "";
  q.addEventListener("input", search);
  search();
})();
