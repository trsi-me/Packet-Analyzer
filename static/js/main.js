/* Packet Analyzer — واجهة عربية، Socket.IO + Chart.js */
(function () {
  "use strict";

  const page = document.body.getAttribute("data-page") || "";

  let socket = null;
  let chartPps = null;
  let chartProto = null;
  let chartTime = null;

  function el(id) {
    return document.getElementById(id);
  }

  function setConnStatus(connected) {
    const dot = el("connStatusDot");
    const text = el("connStatusText");
    if (!dot || !text) return;
    dot.classList.remove("connected", "disconnected");
    if (connected) {
      dot.classList.add("connected");
      text.textContent = "متصل بالخادم";
    } else {
      dot.classList.add("disconnected");
      text.textContent = "منفصل عن الخادم";
    }
  }

  function initSocket() {
    try {
      socket = io({ transports: ["websocket", "polling"] });
      socket.on("connect", function () {
        setConnStatus(true);
      });
      socket.on("disconnect", function () {
        setConnStatus(false);
      });
      socket.on("status", function (data) {
        applyRecordingUi(data.recording);
      });
      socket.on("stats_update", function (data) {
        if (page === "dashboard") updateDashboardStats(data);
      });
      socket.on("new_packet", function (data) {
        if (page === "dashboard" && data.packet) prependRecentRow(data.packet);
      });
    } catch (e) {
      setConnStatus(false);
    }
  }

  function applyRecordingUi(recording) {
    const badge = el("recBadge");
    const btn = el("btnToggleRec");
    if (badge) {
      badge.classList.toggle("active", !!recording);
      badge.textContent = recording ? "نشط" : "متوقف";
    }
    if (btn) {
      btn.textContent = recording ? "أوقف التسجيل" : "ابدأ التسجيل";
      btn.dataset.recording = recording ? "1" : "0";
    }
  }

  function fetchJson(url, options) {
    return fetch(url, options).then(function (r) {
      if (!r.ok) throw new Error(r.statusText);
      return r.json();
    });
  }

  /* ——— لوحة التحكم ——— */
  function initDashboard() {
    const ctxPps = el("chartPps");
    const ctxProto = el("chartProto");
    if (ctxPps) {
      chartPps = new Chart(ctxPps, {
        type: "line",
        data: {
          labels: [],
          datasets: [
            {
              label: "حزم/ثانية",
              data: [],
              borderColor: "#2196f3",
              backgroundColor: "rgba(33, 150, 243, 0.15)",
              fill: true,
              tension: 0.25,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { labels: { color: "#e8f4fd" } } },
          scales: {
            x: { ticks: { color: "#e8f4fd" }, grid: { color: "#1e3a5f" } },
            y: {
              beginAtZero: true,
              ticks: { color: "#e8f4fd" },
              grid: { color: "#1e3a5f" },
            },
          },
        },
      });
    }
    if (ctxProto) {
      chartProto = new Chart(ctxProto, {
        type: "doughnut",
        data: {
          labels: [],
          datasets: [
            {
              data: [],
              backgroundColor: [
                "#2196f3",
                "#1a6ea8",
                "#1a9e75",
                "#e6a817",
                "#c0392b",
                "#9c27b0",
                "#607d8b",
              ],
              borderColor: "#1e3a5f",
              borderWidth: 1,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { labels: { color: "#e8f4fd" } } },
        },
      });
    }

    fetchJson("/api/status")
      .then(function (s) {
        applyRecordingUi(s.recording);
        const hint = el("adminHint");
        if (hint && s.admin === false) {
          hint.textContent =
            "تنبيه: يلزم تشغيل التطبيق كمسؤول لالتقاط الحزم على ويندوز.";
        }
      })
      .catch(function () {});

    fetchJson("/api/stats").then(updateDashboardStats).catch(function () {});
    fetchJson("/api/protocols").then(updateProtoChart).catch(function () {});
    loadRecentTable();

    const btn = el("btnToggleRec");
    if (btn) {
      btn.addEventListener("click", function () {
        const rec = btn.dataset.recording === "1";
        const url = rec ? "/api/stop" : "/api/start";
        const body = {};
        if (!rec) {
          const iface = localStorage.getItem("pa_iface") || "";
          if (iface) body.interface = iface;
        }
        if (rec) applyRecordingUi(false);
        fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        })
          .then(function (r) {
            return r.json().then(function (j) {
              return { ok: r.ok, body: j };
            });
          })
          .then(function (res) {
            if (!res.ok) {
              if (rec) applyRecordingUi(true);
              alert((res.body && res.body.message) || "فشل الطلب");
              return;
            }
            applyRecordingUi(!rec);
            fetchJson("/api/protocols").then(updateProtoChart).catch(function () {});
            loadRecentTable();
          })
          .catch(function () {
            if (rec) applyRecordingUi(true);
            alert("تعذر الاتصال بالخادم.");
          });
      });
    }
  }

  function updateDashboardStats(data) {
    const t = el("statTotal");
    const p = el("statPps");
    const tp = el("statTopProto");
    const ts = el("statTopSrc");
    if (t) t.textContent = data.total_packets != null ? data.total_packets : "0";
    if (p) p.textContent = data.packets_per_second != null ? data.packets_per_second : "0";
    if (tp) {
      tp.textContent =
        data.top_protocol
          ? data.top_protocol + " (" + (data.top_protocol_count || 0) + ")"
          : "—";
    }
    if (ts) {
      ts.textContent =
        data.top_src_ip
          ? data.top_src_ip + " (" + (data.top_src_count || 0) + ")"
          : "—";
    }
    if (chartPps && data.pps_history && data.pps_history.length) {
      const hist = data.pps_history;
      chartPps.data.labels = hist.map(function (_, i) {
        return String(i + 1);
      });
      chartPps.data.datasets[0].data = hist;
      chartPps.update("none");
    }
  }

  function updateProtoChart(protoData) {
    const dist = protoData.distribution || {};
    const labels = Object.keys(dist);
    const values = labels.map(function (k) {
      return dist[k];
    });
    if (chartProto && labels.length) {
      chartProto.data.labels = labels;
      chartProto.data.datasets[0].data = values;
      chartProto.update();
    }
  }

  function loadRecentTable() {
    fetchJson("/api/packets?page=1&per_page=10")
      .then(function (d) {
        const tbody = el("recentPacketsBody");
        if (!tbody) return;
        tbody.innerHTML = "";
        if (!d.packets || !d.packets.length) {
          tbody.innerHTML =
            '<tr><td colspan="6" class="cell-empty">لا توجد بيانات بعد.</td></tr>';
          return;
        }
        d.packets.forEach(function (row) {
          tbody.appendChild(buildPacketRowMini(row));
        });
      })
      .catch(function () {});
  }

  function buildPacketRowMini(row) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" +
      escapeHtml(String(row.id)) +
      "</td>" +
      "<td>" +
      escapeHtml(String(row.timestamp || "")) +
      "</td>" +
      "<td>" +
      escapeHtml(fmtEndpoint(row.src_ip, row.src_port)) +
      "</td>" +
      "<td>" +
      escapeHtml(fmtEndpoint(row.dst_ip, row.dst_port)) +
      "</td>" +
      "<td>" +
      escapeHtml(String(row.protocol || "")) +
      "</td>" +
      "<td>" +
      escapeHtml(String(row.size != null ? row.size : "")) +
      "</td>";
    return tr;
  }

  function prependRecentRow(row) {
    const tbody = el("recentPacketsBody");
    if (!tbody) return;
    const empty = tbody.querySelector(".cell-empty");
    if (empty) empty.closest("tr").remove();
    tbody.insertBefore(buildPacketRowMini(row), tbody.firstChild);
    while (tbody.rows.length > 10) {
      tbody.deleteRow(tbody.rows.length - 1);
    }
  }

  /* ——— الحزم ——— */
  let packetsPage = 1;
  const packetsPerPage = 50;

  function buildExportHref() {
    const params = new URLSearchParams();
    params.set("page", "1");
    params.set("per_page", "100000");
    const proto = el("protoFilter");
    const search = el("searchInput");
    if (proto && proto.value && proto.value !== "all")
      params.set("protocol", proto.value);
    if (search && search.value.trim()) params.set("search", search.value.trim());
    return "/api/export/csv?" + params.toString();
  }

  function initPackets() {
    loadPacketsPage();

    const btnApply = el("btnApplyFilters");
    if (btnApply)
      btnApply.addEventListener("click", function () {
        packetsPage = 1;
        loadPacketsPage();
        const ex = el("btnExportCsv");
        if (ex) ex.href = buildExportHref();
      });

    const search = el("searchInput");
    if (search) {
      let t = null;
      search.addEventListener("input", function () {
        clearTimeout(t);
        t = setTimeout(function () {
          packetsPage = 1;
          loadPacketsPage();
          const ex = el("btnExportCsv");
          if (ex) ex.href = buildExportHref();
        }, 350);
      });
    }

    const proto = el("protoFilter");
    if (proto)
      proto.addEventListener("change", function () {
        packetsPage = 1;
        loadPacketsPage();
        const ex = el("btnExportCsv");
        if (ex) ex.href = buildExportHref();
      });

    el("btnPrevPage") &&
      el("btnPrevPage").addEventListener("click", function () {
        if (packetsPage > 1) {
          packetsPage--;
          loadPacketsPage();
        }
      });
    el("btnNextPage") &&
      el("btnNextPage").addEventListener("click", function () {
        packetsPage++;
        loadPacketsPage();
      });

    const ex = el("btnExportCsv");
    if (ex) ex.href = buildExportHref();

    const modal = el("detailModal");
    el("btnCloseModal") &&
      el("btnCloseModal").addEventListener("click", function () {
        if (modal) modal.hidden = true;
      });
    if (modal)
      modal.addEventListener("click", function (e) {
        if (e.target.dataset.close) modal.hidden = true;
      });
  }

  function loadPacketsPage() {
    const params = new URLSearchParams();
    params.set("page", String(packetsPage));
    params.set("per_page", String(packetsPerPage));
    const proto = el("protoFilter");
    const search = el("searchInput");
    if (proto && proto.value && proto.value !== "all")
      params.set("protocol", proto.value);
    if (search && search.value.trim()) params.set("search", search.value.trim());

    fetchJson("/api/packets?" + params.toString())
      .then(function (d) {
        const tbody = el("packetsTableBody");
        const pageInfo = el("pageInfo");
        if (pageInfo)
          pageInfo.textContent =
            "صفحة " +
            d.page +
            " من " +
            d.pages +
            " — إجمالي " +
            d.total;
        if (!tbody) return;
        tbody.innerHTML = "";
        if (!d.packets || !d.packets.length) {
          tbody.innerHTML =
            '<tr><td colspan="8" class="cell-empty">لا توجد نتائج.</td></tr>';
          return;
        }
        d.packets.forEach(function (row) {
          const tr = document.createElement("tr");
          tr.innerHTML =
            "<td>" +
            escapeHtml(String(row.id)) +
            "</td>" +
            "<td>" +
            escapeHtml(String(row.timestamp || "")) +
            "</td>" +
            "<td>" +
            escapeHtml(fmtEndpoint(row.src_ip, row.src_port)) +
            "</td>" +
            "<td>" +
            escapeHtml(fmtEndpoint(row.dst_ip, row.dst_port)) +
            "</td>" +
            "<td>" +
            escapeHtml(String(row.protocol || "")) +
            "</td>" +
            "<td>" +
            escapeHtml(String(row.size != null ? row.size : "")) +
            "</td>" +
            "<td>" +
            escapeHtml(shortText(row.raw_summary || "", 40)) +
            "</td>" +
            '<td><button type="button" class="btn btn-secondary btn-sm-pkt" data-id="' +
            row.id +
            '">عرض</button></td>';
          tbody.appendChild(tr);
        });
        tbody.querySelectorAll(".btn-sm-pkt").forEach(function (b) {
          b.addEventListener("click", function () {
            openPacketDetail(Number(b.getAttribute("data-id")));
          });
        });
      })
      .catch(function () {
        const tbody = el("packetsTableBody");
        if (tbody)
          tbody.innerHTML =
            '<tr><td colspan="8" class="cell-empty">تعذر تحميل البيانات.</td></tr>';
      });
  }

  function openPacketDetail(id) {
    fetchJson("/api/packets/" + id)
      .then(function (row) {
        const content = el("detailContent");
        const modal = el("detailModal");
        if (!content || !modal) return;
        const lines = [
          "المعرف: " + row.id,
          "الوقت: " + row.timestamp,
          "المصدر: " + fmtEndpoint(row.src_ip, row.src_port),
          "الوجهة: " + fmtEndpoint(row.dst_ip, row.dst_port),
          "البروتوكول: " + row.protocol,
          "الحجم: " + row.size,
          "TTL: " + (row.ttl != null ? row.ttl : "—"),
          "",
          "ملخص:",
          row.raw_summary || "",
          "",
          "المحتوى / الحمولة:",
          row.payload || "(فارغ)",
        ];
        content.textContent = lines.join("\n");
        modal.hidden = false;
      })
      .catch(function () {
        alert("تعذر جلب تفاصيل الحزمة.");
      });
  }

  /* ——— التحليل ——— */
  function initAnalysis() {
    loadTopIps();
    loadProtoPercent();
    loadPorts();
    loadTimeChart("hour");
    loadAnomalies();

    document.querySelectorAll(".btn-bucket").forEach(function (b) {
      b.addEventListener("click", function () {
        document.querySelectorAll(".btn-bucket").forEach(function (x) {
          x.classList.remove("active");
        });
        b.classList.add("active");
        loadTimeChart(b.getAttribute("data-bucket"));
      });
    });

    setInterval(function () {
      loadTopIps();
      loadProtoPercent();
      loadPorts();
      loadAnomalies();
    }, 5000);
  }

  function loadTopIps() {
    fetchJson("/api/top-ips?limit=10")
      .then(function (d) {
        renderBarList("topSrcList", d.src || []);
        renderBarList("topDstList", d.dst || []);
      })
      .catch(function () {});
  }

  function renderBarList(containerId, items) {
    const c = el(containerId);
    if (!c) return;
    const max = items.length
      ? Math.max.apply(
          null,
          items.map(function (x) {
            return x.count;
          })
        )
      : 1;
    c.innerHTML = "";
    items.forEach(function (it) {
      const pct = Math.round((it.count / max) * 100);
      const div = document.createElement("div");
      div.className = "bar-item";
      div.innerHTML =
        '<div><div class="bar-track"><div class="bar-fill" style="width:' +
        pct +
        '%"></div></div><div style="margin-top:4px">' +
        escapeHtml(it.ip) +
        "</div></div><div>" +
        it.count +
        "</div>";
      c.appendChild(div);
    });
  }

  function loadProtoPercent() {
    fetchJson("/api/protocol-percentages")
      .then(function (d) {
        const box = el("protoPercent");
        if (!box) return;
        const p = d.percentages || {};
        box.innerHTML = "";
        Object.keys(p).forEach(function (k) {
          const div = document.createElement("div");
          div.className = "proto-chip";
          div.textContent = k + ": " + p[k] + "%";
          box.appendChild(div);
        });
      })
      .catch(function () {});
  }

  function loadPorts() {
    fetchJson("/api/analysis/ports")
      .then(function (d) {
        const box = el("portsTable");
        if (!box) return;
        const rows = d.ports || [];
        let html =
          '<table class="data-table"><thead><tr><th>المنفذ</th><th>العدد</th></tr></thead><tbody>';
        rows.forEach(function (r) {
          html +=
            "<tr><td>" +
            escapeHtml(String(r.port)) +
            "</td><td>" +
            r.count +
            "</td></tr>";
        });
        html += "</tbody></table>";
        if (!rows.length) html = "<p>لا توجد بيانات.</p>";
        box.innerHTML = html;
      })
      .catch(function () {});
  }

  function loadTimeChart(bucket) {
    fetchJson("/api/analysis/time?bucket=" + encodeURIComponent(bucket))
      .then(function (d) {
        const ctx = el("chartTime");
        if (!ctx) return;
        const series = d.series || [];
        const labels = series.map(function (x) {
          return String(x.label);
        });
        const vals = series.map(function (x) {
          return x.count;
        });
        if (chartTime) chartTime.destroy();
        chartTime = new Chart(ctx, {
          type: "bar",
          data: {
            labels: labels,
            datasets: [
              {
                label: "عدد الحزم",
                data: vals,
                backgroundColor: "rgba(33, 150, 243, 0.45)",
                borderColor: "#2196f3",
                borderWidth: 1,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: "#e8f4fd" } } },
            scales: {
              x: { ticks: { color: "#e8f4fd", maxRotation: 45 }, grid: { color: "#1e3a5f" } },
              y: {
                beginAtZero: true,
                ticks: { color: "#e8f4fd" },
                grid: { color: "#1e3a5f" },
              },
            },
          },
        });
      })
      .catch(function () {});
  }

  function loadAnomalies() {
    fetchJson("/api/analysis/anomalies")
      .then(function (a) {
        const box = el("anomalyBox");
        if (!box) return;
        let html = "";
        if (a.spike_detected) {
          html +=
            '<div class="anomaly-flag warn">تم رصد ارتفاع مفاجئ في الحركة مقارنة بالنافذة السابقة.</div>';
        } else {
          html +=
            '<div class="anomaly-flag ok">لا يوجد ارتفاع شاذ واضح في النافذة الأخيرة.</div>';
        }
        html +=
          "<p>الحزم في آخر 5 دقائق: " +
          a.packets_last_5m +
          " — في الـ5 دقائق السابقة: " +
          a.packets_prev_5m +
          "</p>";
        if (a.suspicious_ports && a.suspicious_ports.length) {
          html += "<p>منافذ ذات نشاط (قائمة مراقبة):</p><ul>";
          a.suspicious_ports.forEach(function (s) {
            html +=
              "<li>المنفذ " + s.port + ": " + s.count + " حزمة</li>";
          });
          html += "</ul>";
        } else {
          html += "<p>لا نشاط على المنافذ المحددة في قائمة المراقبة.</p>";
        }
        box.innerHTML = html;
      })
      .catch(function () {});
  }

  /* ——— الفلاتر ——— */
  function initFilters() {
    el("btnApplyFilter") &&
      el("btnApplyFilter").addEventListener("click", function () {
        applyFilterResults();
      });
    el("btnResetFilter") &&
      el("btnResetFilter").addEventListener("click", function () {
        ["fSrcIp", "fDstIp", "fProto", "fPort", "fFrom", "fTo", "fSizeMin", "fSizeMax"].forEach(
          function (id) {
            const x = el(id);
            if (x) x.value = "";
          }
        );
      });
    el("btnSaveFilter") &&
      el("btnSaveFilter").addEventListener("click", function () {
        const name = (el("saveFilterName") && el("saveFilterName").value) || "";
        if (!name.trim()) {
          alert("أدخل اسماً للفلتر.");
          return;
        }
        const spec = collectFilterSpec();
        fetch("/api/filters/save", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name.trim(), filter: spec }),
        })
          .then(function (r) {
            return r.json().then(function (j) {
              return { ok: r.ok, body: j };
            });
          })
          .then(function (res) {
            if (!res.ok) alert(res.body.message || "فشل الحفظ");
            else loadSavedFilters();
          })
          .catch(function () {
            alert("تعذر الحفظ.");
          });
      });
    loadSavedFilters();
  }

  function collectFilterSpec() {
    return {
      src_ip: el("fSrcIp") && el("fSrcIp").value.trim(),
      dst_ip: el("fDstIp") && el("fDstIp").value.trim(),
      protocol: el("fProto") && el("fProto").value,
      port: el("fPort") && el("fPort").value.trim(),
      time_from: normalizeDt(el("fFrom") && el("fFrom").value),
      time_to: normalizeDt(el("fTo") && el("fTo").value),
      size_min: el("fSizeMin") && el("fSizeMin").value,
      size_max: el("fSizeMax") && el("fSizeMax").value,
    };
  }

  function normalizeDt(v) {
    if (!v) return "";
    return v.replace("T", " ") + (v.length === 16 ? ":00" : "");
  }

  function applyFilterResults() {
    const spec = collectFilterSpec();
    const params = new URLSearchParams();
    params.set("page", "1");
    params.set("per_page", "50");
    if (spec.src_ip) params.set("src_ip", spec.src_ip);
    if (spec.dst_ip) params.set("dst_ip", spec.dst_ip);
    if (spec.protocol) params.set("protocol", spec.protocol);
    if (spec.port) params.set("port", spec.port);
    if (spec.time_from) params.set("time_from", spec.time_from);
    if (spec.time_to) params.set("time_to", spec.time_to);
    if (spec.size_min) params.set("size_min", spec.size_min);
    if (spec.size_max) params.set("size_max", spec.size_max);

    fetchJson("/api/packets?" + params.toString())
      .then(function (d) {
        const tbody = el("filterResultsBody");
        if (!tbody) return;
        tbody.innerHTML = "";
        if (!d.packets || !d.packets.length) {
          tbody.innerHTML =
            '<tr><td colspan="6" class="cell-empty">لا توجد نتائج.</td></tr>';
          return;
        }
        d.packets.forEach(function (row) {
          const tr = document.createElement("tr");
          tr.innerHTML =
            "<td>" +
            escapeHtml(String(row.id)) +
            "</td>" +
            "<td>" +
            escapeHtml(String(row.timestamp || "")) +
            "</td>" +
            "<td>" +
            escapeHtml(fmtEndpoint(row.src_ip, row.src_port)) +
            "</td>" +
            "<td>" +
            escapeHtml(fmtEndpoint(row.dst_ip, row.dst_port)) +
            "</td>" +
            "<td>" +
            escapeHtml(String(row.protocol || "")) +
            "</td>" +
            "<td>" +
            escapeHtml(String(row.size != null ? row.size : "")) +
            "</td>";
          tbody.appendChild(tr);
        });
      })
      .catch(function () {
        alert("تعذر تطبيق الفلتر.");
      });
  }

  function loadSavedFilters() {
    fetchJson("/api/filters")
      .then(function (d) {
        const box = el("savedFiltersList");
        if (!box) return;
        box.innerHTML = "";
        (d.filters || []).forEach(function (f) {
          const div = document.createElement("div");
          div.className = "saved-filter-item";
          const span = document.createElement("span");
          const strong = document.createElement("strong");
          strong.textContent = f.name || "";
          span.appendChild(strong);
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "btn btn-secondary";
          btn.textContent = "تطبيق";
          btn.addEventListener("click", function () {
            try {
              const j = JSON.parse(f.filter_json || "{}");
              if (el("fSrcIp")) el("fSrcIp").value = j.src_ip || "";
              if (el("fDstIp")) el("fDstIp").value = j.dst_ip || "";
              if (el("fProto")) el("fProto").value = j.protocol || "";
              if (el("fPort")) el("fPort").value = j.port || "";
              if (el("fSizeMin")) el("fSizeMin").value = j.size_min || "";
              if (el("fSizeMax")) el("fSizeMax").value = j.size_max || "";
              if (j.time_from && el("fFrom"))
                el("fFrom").value = String(j.time_from).replace(" ", "T").slice(0, 16);
              if (j.time_to && el("fTo"))
                el("fTo").value = String(j.time_to).replace(" ", "T").slice(0, 16);
              applyFilterResults();
            } catch (err) {
              alert("تعذر قراءة الفلتر المحفوظ.");
            }
          });
          div.appendChild(span);
          div.appendChild(btn);
          box.appendChild(div);
        });
      })
      .catch(function () {});
  }

  /* ——— الإعدادات ——— */
  function initSettings() {
    loadInterfaces();
    fetchJson("/api/settings")
      .then(function (s) {
        const maxp = el("maxPackets");
        if (maxp && s.max_packets != null) maxp.value = s.max_packets;
        const iface = el("ifaceSelect");
        if (iface && s.interface) iface.value = s.interface;
        const dbSize = el("dbSizeText");
        if (dbSize && s.db_size_bytes != null)
          dbSize.textContent = formatBytes(s.db_size_bytes);
      })
      .catch(function () {});

    el("btnRefreshIfaces") &&
      el("btnRefreshIfaces").addEventListener("click", loadInterfaces);
    el("btnSaveSettings") &&
      el("btnSaveSettings").addEventListener("click", function () {
        const iface = el("ifaceSelect") ? el("ifaceSelect").value : "";
        const maxp = el("maxPackets") ? parseInt(el("maxPackets").value, 10) : 100000;
        fetch("/api/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ interface: iface, max_packets: maxp }),
        })
          .then(function (r) {
            return r.json().then(function (j) {
              return { ok: r.ok, data: j };
            });
          })
          .then(function (res) {
            if (!res.ok) {
              alert((res.data && res.data.message) || "فشل الحفظ.");
              return;
            }
            localStorage.setItem("pa_iface", iface);
            alert("تم حفظ الإعدادات.");
            const s = res.data.settings || {};
            const dbSize = el("dbSizeText");
            return fetchJson("/api/settings").then(function (full) {
              if (dbSize && full.db_size_bytes != null)
                dbSize.textContent = formatBytes(full.db_size_bytes);
            });
          })
          .catch(function () {
            alert("فشل الحفظ.");
          });
      });

    el("btnClearAll") &&
      el("btnClearAll").addEventListener("click", function () {
        if (
          !confirm(
            "سيتم حذف بيانات الحزم وسجلات الجلسات فقط (لا يُمسح الفلاتر المحفوظة). متابعة؟"
          )
        )
          return;
        fetch("/api/clear", { method: "POST" })
          .then(function (r) {
            return r.json();
          })
          .then(function () {
            alert("تم حذف البيانات.");
            return fetchJson("/api/settings");
          })
          .then(function (s) {
            const dbSize = el("dbSizeText");
            if (dbSize && s.db_size_bytes != null)
              dbSize.textContent = formatBytes(s.db_size_bytes);
          })
          .catch(function () {
            alert("تعذر الحذف.");
          });
      });
  }

  function loadInterfaces() {
    fetchJson("/api/interfaces")
      .then(function (d) {
        const sel = el("ifaceSelect");
        if (!sel) return;
        const cur = sel.value;
        sel.innerHTML = '<option value="">افتراضي النظام</option>';
        (d.interfaces || []).forEach(function (x) {
          const o = document.createElement("option");
          o.value = x.name;
          o.textContent = x.name;
          sel.appendChild(o);
        });
        if (cur) sel.value = cur;
      })
      .catch(function () {});
  }

  function formatBytes(n) {
    if (n < 1024) return n + " بايت";
    if (n < 1048576) return (n / 1024).toFixed(1) + " ك.ب";
    return (n / 1048576).toFixed(2) + " م.ب";
  }

  function fmtEndpoint(ip, port) {
    if (port != null && port !== "") return ip + ":" + port;
    return ip || "—";
  }

  function shortText(s, n) {
    if (!s) return "";
    s = String(s);
    return s.length > n ? s.slice(0, n) + "…" : s;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  document.addEventListener("DOMContentLoaded", function () {
    initSocket();
    if (page === "dashboard") initDashboard();
    else if (page === "packets") initPackets();
    else if (page === "analysis") initAnalysis();
    else if (page === "filters") initFilters();
    else if (page === "settings") initSettings();
  });
})();
