async function createHPCTable({
    elId,
    apiUrl,
    searchId = null,
    exportBtnId = null,
    refreshBtnId = null,
    clearFiltersBtnId = null,
  }) {
    const el = document.getElementById(elId);
    if (!el) return console.error("Missing table element:", elId);
  
    // First call to get columns + table settings
    const metaResp = await fetch(`${apiUrl}?page=1&size=1`, { credentials: "same-origin" });
    if (!metaResp.ok) return console.error("Meta fetch failed:", metaResp.status);
    const meta = await metaResp.json();
  
    const serverSettings = meta.tabulator_settings || {};
    const batchSize = serverSettings.paginationSize || 300;
  
    const useScroll = serverSettings.progressiveLoad === "scroll";
  
    const columns = (meta.columns || []).map((c) => {
      if (!("headerFilter" in c)) c.headerFilter = "input";
      if (!("headerFilterFunc" in c)) c.headerFilterFunc = "like";
      return c;
    });
  
    // Keep last search text so it is applied with filters
    let currentSearch = "";
  
    // Convert Tabulator filters -> query params your Django API can understand
    function tabulatorFiltersToParams(filters) {
      // Example filters:
      // [{field:"hostname", type:"like", value:"dcwi"}]
      const params = {};
      (filters || []).forEach((f) => {
        if (!f.field || f.value === "" || f.value == null) return;
  
        // Map Tabulator filter types to Django lookups
        // Most header filters are "like" -> icontains
        let lookup = "icontains";
  
        if (f.type === "=" || f.type === "equals") lookup = "exact";
        else if (f.type === "!=") lookup = "exact"; // handle separately if you want
        else if (f.type === "starts") lookup = "istartswith";
        else if (f.type === "ends") lookup = "iendswith";
        else if (f.type === "like") lookup = "icontains";
  
        params[`${f.field}__${lookup}`] = f.value;
      });
      return params;
    }
  
    // This makes Tabulator generate URLs that include filters/search/paging
    function ajaxURLGenerator(url, config, params) {
      const u = new URL(url, window.location.origin);
  
      // paging/progressive scroll params
      if (params && params.page) u.searchParams.set("page", params.page);
      u.searchParams.set("size", batchSize);
  
      // search (q)
      if (currentSearch) u.searchParams.set("q", currentSearch);
  
      // header filters (remote)
      const filterParams = tabulatorFiltersToParams(params?.filter);
      Object.entries(filterParams).forEach(([k, v]) => u.searchParams.set(k, v));
  
      return u.toString();
    }
  
    const table = new Tabulator(el, {
      height: "100%",
      layout: "fitColumns",
      columns,
  
      ajaxURL: apiUrl,
      ajaxConfig: { method: "GET", credentials: "same-origin" },
      ajaxURLGenerator,
  
      // Remote pagination required for progressive scroll
      pagination: true,
      paginationMode: "remote",
      paginationSize: batchSize,
  
      progressiveLoad: useScroll ? "scroll" : false,
      progressiveLoadScrollMargin: serverSettings.progressiveLoadScrollMargin || 400,
  
      // Remote filter mode
      filterMode: serverSettings.filterMode || "remote",
  
      ajaxResponse: function (url, params, resp) {
        return { data: resp.data || [], last_page: resp.last_page || 1 };
      },
  
      ...serverSettings,
    });
  
    // Initial load
    table.setData(apiUrl, { page: 1, size: batchSize });
  
    // Search box -> reload from server (page 1)
    if (searchId) {
      const searchEl = document.getElementById(searchId);
      if (searchEl) {
        let t = null;
        searchEl.addEventListener("input", (e) => {
          clearTimeout(t);
          t = setTimeout(() => {
            currentSearch = (e.target.value || "").trim();
            table.setData(apiUrl, { page: 1 });
          }, 250);
        });
      }
    }
  
    // Refresh
    if (refreshBtnId) {
      document.getElementById(refreshBtnId)?.addEventListener("click", () => {
        table.setData(apiUrl, { page: 1 });
      });
    }
  
    // Clear filters + search
    if (clearFiltersBtnId) {
      document.getElementById(clearFiltersBtnId)?.addEventListener("click", () => {
        currentSearch = "";
        if (searchId) {
          const searchEl = document.getElementById(searchId);
          if (searchEl) searchEl.value = "";
        }
        table.clearHeaderFilter();
        table.clearFilter(true);
        table.setData(apiUrl, { page: 1 });
      });
    }
  
    // Export all (server-side export) with current filters/search
    if (exportBtnId) {
      document.getElementById(exportBtnId)?.addEventListener("click", () => {
        const u = new URL(`${apiUrl}export/csv/`, window.location.origin);
  
        if (currentSearch) u.searchParams.set("q", currentSearch);
  
        // include current header filters in export
        const filters = table.getFilters();
        const filterParams = tabulatorFiltersToParams(filters);
        Object.entries(filterParams).forEach(([k, v]) => u.searchParams.set(k, v));
  
        window.location.href = u.toString();
      });
    }
  
    return table;
  }
  