/* Dashboard islands. Vanilla JS, no build step, no external calls.

   Everything here is progressive enhancement: every control is a real link or
   form field that works without this file. The islands only avoid full page
   loads.

   - range:   nothing to do; the picker is plain links.
   - domains: sort / search / gaps-only / paging fetch the table fragment and
              swap it in, updating the URL so reload and back/forward hold.
   - sources: filter + "unclassified only" are DOM-only over the rendered rows. */

(function () {
  "use strict";

  // ── Domains table ────────────────────────────────────────────────────────

  const domains = document.querySelector('[data-island="domains"]');
  if (domains) {
    const form = domains.querySelector("#domains-controls");
    const slot = domains.querySelector("#domains-table-slot");
    const caption = domains.querySelector("#domains-caption");
    const fragment = domains.dataset.fragment;
    const days = domains.dataset.days;

    const state = {
      q: form.elements.q.value || "",
      gaps: form.elements.gaps.checked ? 1 : 0,
      sort: form.elements.sort.value || "name",
      dir: form.elements.dir.value || "asc",
      page: 0,
    };

    function query() {
      const p = new URLSearchParams();
      p.set("days", days);
      p.set("q", state.q);
      p.set("gaps", String(state.gaps));
      p.set("sort", state.sort);
      p.set("dir", state.dir);
      p.set("page", String(state.page));
      return p.toString();
    }

    let inflight = null;
    async function refresh(push) {
      if (inflight) inflight.abort();
      inflight = new AbortController();
      slot.setAttribute("aria-busy", "true");
      try {
        const res = await fetch(fragment + "?" + query(), {
          signal: inflight.signal,
          headers: { Accept: "text/html" },
        });
        if (!res.ok) throw new Error(String(res.status));
        slot.innerHTML = await res.text();
        const table = slot.querySelector("#domains-table");
        if (table) state.page = Number(table.dataset.page) || 0;
        const range = slot.querySelector(".dtable__range");
        if (range && caption) {
          const m = /of (\d+)/.exec(range.textContent || "");
          if (m) caption.textContent = m[1] + " of " + caption.textContent.split(" of ")[1];
        }
        if (push) history.replaceState(null, "", "/domains?" + query());
      } catch (err) {
        if (err.name !== "AbortError") form.submit(); // fall back to a full load
      } finally {
        slot.removeAttribute("aria-busy");
      }
    }

    // Sorting and paging: intercept the links the server rendered.
    slot.addEventListener("click", function (e) {
      const sortLink = e.target.closest("[data-sort]");
      if (sortLink) {
        e.preventDefault();
        const key = sortLink.dataset.sort;
        if (state.sort === key) state.dir = state.dir === "asc" ? "desc" : "asc";
        else { state.sort = key; state.dir = "asc"; }
        state.page = 0;
        form.elements.sort.value = state.sort;
        form.elements.dir.value = state.dir;
        refresh(true);
        return;
      }
      const pageLink = e.target.closest("[data-page]");
      if (pageLink && !pageLink.classList.contains("btn--disabled")) {
        e.preventDefault();
        state.page = Math.max(0, Number(pageLink.dataset.page) || 0);
        refresh(true);
      }
    });

    let timer = null;
    form.elements.q.addEventListener("input", function () {
      clearTimeout(timer);
      timer = setTimeout(function () {
        state.q = form.elements.q.value;
        state.page = 0;
        refresh(true);
      }, 180);
    });
    form.elements.gaps.addEventListener("change", function () {
      state.gaps = form.elements.gaps.checked ? 1 : 0;
      state.page = 0;
      refresh(true);
    });
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      state.q = form.elements.q.value;
      state.page = 0;
      refresh(true);
    });
  }

  // ── Sources filter ───────────────────────────────────────────────────────

  const sources = document.querySelector('[data-island="sources"]');
  if (sources) {
    const filter = sources.querySelector("#source-filter");
    const only = sources.querySelector("#unclassified-only");
    const rows = Array.from(sources.querySelectorAll(".srow"));
    const emptyFiltered = sources.querySelector("[data-filter-empty]");

    function apply() {
      const needle = (filter.value || "").trim().toLowerCase();
      let shown = 0;
      rows.forEach(function (row) {
        const ok =
          (!needle || row.dataset.name.indexOf(needle) !== -1) &&
          (!only.checked || row.dataset.class === "unclassified");
        row.hidden = !ok;
        if (ok) shown += 1;
      });
      if (emptyFiltered) emptyFiltered.hidden = !(rows.length > 0 && shown === 0);
    }
    filter.addEventListener("input", apply);
    only.addEventListener("change", apply);
  }
})();
