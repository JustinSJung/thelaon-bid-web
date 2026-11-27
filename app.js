"use strict";
(() => {
  let snapshot = null,
    password = null,
    offset = 0,
    selected = null;
  const $ = (s) => document.querySelector(s);
  const el = (tag, text, cls) => {
    const n = document.createElement(tag);
    if (text != null) n.textContent = text;
    if (cls) n.className = cls;
    return n;
  };
  const money = (value) =>
    value == null
      ? "확인 전"
      : new Intl.NumberFormat("ko-KR", { maximumFractionDigits: 0 }).format(
          Number(value),
        ) + "원";
  const date = (value) =>
    value && Number.isFinite(Date.parse(value))
      ? new Intl.DateTimeFormat("ko-KR", {
          dateStyle: "short",
          timeStyle: "short",
          timeZone: "Asia/Seoul",
        }).format(new Date(value)) + " KST"
      : "확인 필요";
  const b64 = (s) => {
    const binary = atob(s), bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  };
  const clear = (n) => {
    n.replaceChildren();
    return n;
  };
  function link(url, text) {
    const n = el("a", text);
    try {
      const u = new URL(url);
      if (!["http:", "https:"].includes(u.protocol))
        return el("span", "출처 확인 필요");
      n.href = u.href;
      n.target = "_blank";
      n.rel = "noopener noreferrer";
    } catch {
      return el("span", "출처 확인 필요");
    }
    return n;
  }
  function table(headers, rows) {
    const t = el("table"),
      h = el("tr");
    headers.forEach((s) => h.append(el("th", s)));
    const th = el("thead");
    th.append(h);
    t.append(th);
    const b = el("tbody");
    for (const values of rows) {
      const r = el("tr");
      values.forEach((v) => {
        const td = el("td");
        td.append(v instanceof Node ? v : el("span", v ?? "확인 전"));
        r.append(td);
      });
      b.append(r);
    }
    t.append(b);
    return t;
  }
  function list(root, values) {
    const ul = el("ul");
    values.forEach((v) => ul.append(el("li", v)));
    root.append(ul);
  }
  let encryptedPromise = null, encryptedAt = 0;
  function encryptedSnapshot(refresh = false) {
    if (!encryptedPromise || refresh || Date.now() - encryptedAt > 5 * 60 * 1000) {
      encryptedAt = Date.now();
      const pending = fetch("./snapshot.enc.json", {
        cache: "no-cache", credentials: "omit", referrerPolicy: "no-referrer",
      }).then(async (response) => {
        if (!response.ok) throw new Error("최신 분석 자료가 아직 준비되지 않았습니다.");
        const e = await response.json();
        if (!["thelaon:web:v1", "thelaon:web:v2:gzip"].includes(e.format) || e.iterations !== 600000)
          throw new Error("페이지를 새로고침한 후 다시 열어주세요.");
        return e;
      });
      encryptedPromise = pending;
      pending.catch(() => { if (encryptedPromise === pending) encryptedPromise = null; });
    }
    return encryptedPromise;
  }
  async function decryptData(e,secret) {
    if (!["thelaon:web:v1","thelaon:web:v2:gzip"].includes(e.format) || e.iterations!==600000)throw new Error("자료 형식 확인 필요");
    const base = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: b64(e.salt),
        iterations: e.iterations,
      },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    let data;
    try {
      const bytes = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: b64(e.nonce),
          additionalData: new TextEncoder().encode(e.format),
        },
        key,
        b64(e.ciphertext),
      );
      if (e.format === "thelaon:web:v2:gzip") {
        data = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"))).json();
      } else data = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      throw new Error("접속 암호가 다르거나 자료가 변경됐습니다.");
    }
    return data;
  }
  async function unlock(secret, refresh = false) {
    $("#login-status").textContent = "분석 자료 불러오는 중…";
    const e = await encryptedSnapshot(refresh);
    $("#login-status").textContent = "접속 암호 확인 중…";
    if (e.format === "thelaon:web:v2:gzip" && typeof DecompressionStream !== "function")
      throw new Error("압축 해제를 지원하는 최신 브라우저가 필요합니다.");
    const data = await decryptData(e,secret);
    if (data.version !== 1 || !Array.isArray(data.worklist?.rows))
      throw new Error("검토 자료 형식이 올바르지 않습니다.");
    if(historyAbort)historyAbort.abort();historyLoad=null;
    historicalIndex = null;
    snapshot = data;
    password = secret;
    $("#password").value = "";
    $("#login-error").textContent = "";
    $("#login-status").textContent = "";
    $("#login").hidden = true;
    $("#login").style.display = "none";
    $("#app").hidden = false;
    render();
  }
  function currentRows() {
    const now = Date.now();
    return snapshot.worklist.rows.map((original) => {
      const row = { ...original };
      const expired = ["application_deadline", "bid_deadline"].filter(
        (k) => row[k] && Date.parse(row[k]) <= now,
      );
      const kstDay = new Date(now + 9 * 3600000).toISOString().slice(0, 10);
      const dateClosed = !row.bid_deadline && row.bid_end_date && row.bid_end_date < kstDay;
      if (expired.length || dateClosed) {
        row.stage = "excluded";
        row.stage_title = "마감·제외";
        row.reason = dateClosed ? "공시 종료일 경과·정확한 시각은 미확인" : expired
          .map((k) => (k === "bid_deadline" ? "투찰 마감" : "참가신청 마감"))
          .join(" / ");
        row.economics = null;
      } else if (
        row.economics &&
        (!Number.isFinite(Date.parse(row.economics.valid_until)) ||
          Date.parse(row.economics.valid_until) <= now)
      ) {
        row.stage = "document_review";
        row.stage_title = "견적 갱신 필요";
        row.economics = null;
        row.reason = "저장된 공급견적의 유효기간이 지났습니다.";
      }
      return row;
    });
  }
  function render() {
    $("#snapshot-time").textContent =
      "분석 자료 생성 " + date(snapshot.generated_at);
    const age = Date.now() - Date.parse(snapshot.generated_at);
    const failed = snapshot.source_health.filter(
      (r) =>
        r.status !== "success" ||
        !Number.isFinite(Date.parse(r.started_at)) ||
        Date.now() - Date.parse(r.started_at) > 86400000,
    );
    const n = $("#freshness");
    n.className =
      "notice" + (failed.length || age > 86400000 ? " warning" : "");
    n.textContent =
      (age > 86400000 ? "24시간 이상 지난 자료입니다. " : "") +
      (failed.length
        ? failed.length +
          "개 자료에 수집 실패 또는 최근 24시간 수집 기록 부재가 있습니다. "
        : "") +
      "원문·첨부·공급 견적을 확인한 공고만 투찰 검토 대상으로 판단합니다.";
    const rows = currentRows(),
      metrics = clear($("#metrics"));
    for (const [label, count, note] of [
      [
        "검토 중 공고",
        rows.filter((r) => r.stage !== "excluded").length,
        "마감·확인된 제외 사유 제외",
      ],
      [
        "투찰 검토 후보",
        rows.filter((r) => r.stage === "bid_review").length,
        "자료 생성 시점의 근거 기준",
      ],
      ["공급 견적 기록", snapshot.overview.quotes, "유효성 검토와는 별도"],
      ["과거 낙찰 기록", snapshot.overview.history, "금액·규격 검토 후 비교"],
    ]) {
      const c = el("div", null, "metric");
      c.append(
        el("span", label),
        el("strong", count.toLocaleString()),
        el("small", note),
      );
      metrics.append(c);
    }
    const stage = $("#stage"),
      prior = stage.value;
    while (stage.options.length > 2) stage.remove(2);
    snapshot.worklist.stages.forEach((s) => {
      const o = el("option", s.title);
      o.value = s.id;
      stage.append(o);
    });
    stage.value = prior;
    renderRows();
    renderSources();
    showAIStatus();
    renderModel();
    renderPolicy();
    renderFeedback();
    if (selected) showDetail(selected);
  }
  function renderRows() {
    if (!snapshot) return;
    const search = $("#search").value.toLocaleLowerCase(),
      stage = $("#stage").value;
    const rows = currentRows().filter(
      (r) =>
        ($("#source-filter").value === "all" || ($("#source-filter").value === "power" ? r.power_sector : r.source_system === "ALIO API")) &&
        (stage === "all" ||
          (stage === "active" ? r.stage !== "excluded" : r.stage === stage)) &&
        [r.title, r.institution, r.notice_no]
          .join(" ")
          .toLocaleLowerCase()
          .includes(search),
    );
    offset = Math.min(
      offset,
      Math.max(0, Math.floor((rows.length - 1) / 30) * 30),
    );
    $("#count").textContent = rows.length.toLocaleString() + "건";
    $("#page").textContent =
      (rows.length ? offset + 1 : 0) + "–" + Math.min(offset + 30, rows.length);
    $("#previous").disabled = offset === 0;
    $("#next").disabled = offset + 30 >= rows.length;
    const root = clear($("#rows"));
    for (const row of rows.slice(offset, offset + 30)) {
      const b = el(
        "button",
        null,
        "tender" + (selected === row.id ? " selected" : ""),
      );
      b.dataset.id = row.id;
      b.append(
        el(
          "span",
          row.stage_title,
          "badge" +
            (row.stage === "bid_review"
              ? " good"
              : row.stage === "restriction_review"
                ? " warn"
                : ""),
        ),
        el("strong", row.title),
        el(
          "small",
          (row.institution || "기관 확인 필요") + " · " + row.notice_no,
        ),
        el("p", row.next_action, "next"),
        el(
          "small",
          "참가신청 " +
            date(row.application_deadline) +
            " / 투찰 " +
            (row.bid_deadline ? date(row.bid_deadline) : row.bid_end_date ? row.bid_end_date + " (시각 미확인)" : "미확인"),
        ),
      );
      if (row.manual_source) b.append(el("small", "수동 반입 · 원문 미검토"));
      b.onclick = () => {
        selected = row.id;
        renderRows();
        showDetail(row.id);
      };
      root.append(b);
    }
    if (!rows.length)
      root.append(
        el(
          "div",
          "해당 조건의 공고가 없습니다. 수집 상태 또는 다른 검토 단계를 확인하세요.",
          "empty",
        ),
      );
  }
  function showDetail(id) {
    const row = currentRows().find((r) => r.id === id),
      d = snapshot.details[id];
    if (!row || !d) return;
    const root = clear($("#detail"));
    root.append(
      el("span", row.stage_title, "badge"),
      el("h2", row.title),
      el("p", row.institution, "muted"),
      link(row.source_url, "공고 원문 ↗"),
    );
    if (row.manual_source)
      root.append(
        el(
          "p",
          "사용자가 복사한 공고입니다. API 정상 수집 또는 참가자격 확인으로 취급하지 않습니다.",
          "notice warning",
        ),
      );
    const kv = el("div", null, "kv");
    for (const [label, value] of [
      ["추정가격·세금 별도", money(row.estimate_ex_vat)],
      [
        "수량",
        d.quantity
          ? d.quantity + " " + (d.unit || "단위 확인 필요")
          : "규격서 확인 필요",
      ],
      ["참가신청 마감", date(row.application_deadline)],
      ["납기", date(d.delivery_deadline)],
      ["필요 매입자금", money(row.economics?.working_capital)],
      ["투찰 마감", row.bid_deadline ? date(row.bid_deadline) : row.bid_end_date ? row.bid_end_date + " (시각 미확인)" : "미확인"],
    ]) {
      const n = el("div");
      n.append(el("small", label), el("strong", value));
      kv.append(n);
    }
    root.append(
      kv,
      el("h3", "이 순서로 보는 이유"),
      el("p", row.reason),
      el("div", row.next_action, "notice"),
    );
    if (row.condition_clues.length) {
      root.append(el("h3", "참가조건 단서 · 미검토"));
      for (const c of row.condition_clues) {
        root.append(el("p", c.label), el("div", c.excerpt, "quote"));
      }
    }
    const bidButton=el("button","이 공고의 투찰 기록", "primary");bidButton.onclick=()=>chooseFeedback(id);root.append(bidButton);
    renderSpecification(root,d);
    renderHistory(root,d);
    renderMarketDiscovery(root,d);
    root.append(el("h3", "확인된 시장가격"));
    const market = d.market.verified_prices.filter(
      (p) => Date.parse(p.valid_until) > Date.now(),
    );
    if (market.length)
      root.append(
        table(
          ["공급처", "국가", "단가·세금 별도", "출처"],
          market.map((p) => [
            p.supplier,
            p.country,
            money(p.unit_price),
            link(p.source, "근거 ↗"),
          ]),
        ),
      );
    else
      root.append(
        el(
          "p",
          "동일 규격·수량·세금 기준을 검토한 가격이 없습니다. 공급사 견적이 필요합니다.",
          "muted",
        ),
      );
    root.append(el("h3", "전체 납품원가 · 투찰가격"));
    const e = row.economics;
    if (e) {
      const box = el("div", null, "data-card");
      box.append(
        el("p", "공급처 " + e.supplier),
        el(
          "p",
          "납품원가 " +
            money(e.total_cost_ex_vat) +
            " / 필요자금 " +
            money(e.working_capital),
        ),
        el(
          "p",
          "최소 이익·자금 기준을 반영한 가격 " + money(e.minimum_viable_bid),
        ),
        el("p", "검토용 투찰안 " + money(e.recommended_bid)),
        el("small", "생성 시점의 검토 근거 기준. 낙찰 확률은 검증 전입니다."),
      );
      root.append(box);
    } else
      root.append(
        el(
          "p",
          "검토된 전체 수량 공급견적이 없어 원가·이익·추천 투찰가를 계산하지 않았습니다.",
          "muted",
        ),
      );
    if (d.attachments?.length) {
      root.append(el("h3", "공고문 · 규격서"));
      for (const a of d.attachments) {
        const p = el("p");
        p.append(link(a.url, a.name || "첨부파일"));
        root.append(p);
      }
    }
    if (d.eligibility_text) {
      const details = el("details");
      details.append(
        el("summary", "API 참가조건 원문"),
        el("div", d.eligibility_text, "quote"),
      );
      root.append(details);
    }
    root.append(el("h3", "견적 문의 초안"));
    const draft = el("textarea");
    draft.readOnly = true;
    draft.setAttribute("aria-label", "견적 문의 초안");
    draft.value =
      "제목: 공급 견적 및 규격 충족 확인 요청 — " +
      row.title +
      "\n\n안녕하세요. 더라온입니다. 아래 물품의 공급 가능 여부와 견적을 요청드립니다.\n\n품목·규격: " +
      (d.spec_text || row.title) +
      "\n수량: " +
      (d.quantity || "[확인 필요]") +
      " " +
      (d.unit || "") +
      "\n납품기한: " +
      (d.delivery_deadline || "[확인 필요]") +
      "\n공고: " +
      (row.source_url || "") +
      "\n\n제조사·모델·원산지, 데이터시트, MOQ·포장단위, 단가·통화·부가세, 견적 유효기간, 재고·납기, 운송·관세 포함 범위, 결제조건, 인증·시험성적서와 공급확약 가능 여부를 부탁드립니다.\n\n더라온\n[담당자 이름·연락처]";
    const copy = el("button", "문의 내용 복사");
    copy.onclick = async () => {
      try {
        await navigator.clipboard.writeText(draft.value);
        copy.textContent = "복사했습니다";
      } catch {
        draft.focus();
        draft.select();
        copy.textContent = "선택된 내용을 복사하세요";
      }
    };
    root.append(
      draft,
      copy,
      el("small", "초안만 생성합니다. 메일을 발송하지 않습니다."),
    );
  }
  function renderSources() {
    const root = clear($("#sources"));
    root.append(
      el("h2", "기관별 실제 수집 상태"),
      el(
        "p",
        "아직 전 공공기관의 완전 수집은 완료되지 않았습니다. 실패·미연결은 공고 0건과 구분합니다.",
        "notice",
      ),
      table(
        ["자료", "최근 시도", "조회 종료", "상태", "응답 수"],
        snapshot.source_health.map((r) => [
          r.stream,
          date(r.started_at),
          date(r.end),
          r.status === "success"
            ? "수집 성공"
            : "미완료 · " + (r.detail || r.status),
          r.records,
        ]),
      ),
    );
  }
  function showAIStatus() {
    const failures = (snapshot.last_research_attempts || []).filter(
      (r) => r.status === "failed",
    );
    if (failures.length) {
      const card = el("div", null, "data-card");
      card.append(
        el("h3", "AI 공개 문서 분석"),
        el(
          "p",
          failures[0].detail || "최근 요청 미완료. 결과로 저장하지 않았습니다.",
          "notice warning",
        ),
      );
      $("#sources").append(card);
    }
  }
  function renderModel() {
    const root = clear($("#model")),
      m = snapshot.overview.model;
    root.append(
      el("h2", "검증된 낙찰가격 근거"),
      el(
        "p",
        m.approved ? "저장된 모델 검증 기준 통과" : "실제 예측 사용 보류",
        "notice",
      ),
      el("p", m.reason || m.status),
      el("p", "근거가 검토된 학습자료 " + (m.accepted_count ?? 0) + "건"),
      el(
        "p",
        "낙찰 확률 모델은 아직 검증되지 않았습니다. API에서 수집한 과거 금액을 세금·총액·규격 대조 없이 학습에 넣지 않습니다.",
      ),
    );
  }
  function renderPolicy() {
    const root = clear($("#policy")),
      p = snapshot.profile;
    root.append(
      el("h2", p.name + "의 사업 기준"),
      el(
        "p",
        p.address + " · 비제조 유통·납품 · 소상공인 확인서 보유(사용자 진술)",
      ),
      table(
        ["항목", "설정"],
        [
          ["최소 이익금", money(p.minimum_profit_krw)],
          [
            "최소 매출 이익률",
            p.minimum_margin == null
              ? "미정"
              : Number(p.minimum_margin) * 100 + "%",
          ],
          ["건당 매입자금 한도", money(p.maximum_working_capital_krw)],
        ],
      ),
      el(
        "p",
        "기준이 미정이면 이익·자금 조건을 임의로 채워 추천하지 않습니다. 현재 웹 화면은 생성된 분석을 조회하며, 기존 편집 워크벤치에서 입력한 기록은 동기화 후 반영됩니다.",
        "notice",
      ),
    );
  }
  if ($("#intake-form"))
    $("#intake-form").onsubmit = (event) => {
      event.preventDefault();
      const root = $("#intake-error");
      root.textContent = "";
      $("#intake-ready").hidden = true;
      $("#intake-packet").value = "";
      try {
        const values = Object.fromEntries(new FormData(event.currentTarget));
        const source = new URL(values.source_url);
        if (
          source.protocol !== "https:" ||
          source.hostname !== "srm.kepco.net" ||
          source.username ||
          source.password ||
          source.port
        )
          throw new Error("한전 SRM의 HTTPS 원문 주소를 입력하세요.");
        if (
          /;jsessionid=/i.test(source.href) ||
          [
            ...source.searchParams.keys(),
            ...new URLSearchParams(source.hash.slice(1)).keys(),
          ].some((k) =>
            /password|passwd|token|apikey|api_key|cookie|secret|session/i.test(
              k,
            ),
          )
        )
          throw new Error("원문 주소에 인증 정보가 포함돼 있습니다.");
        if (
          /-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----/.test(
            values.notice_text,
          )
        )
          throw new Error(
            "공고문만 입력하세요. 인증서·비밀키는 반입하지 않습니다.",
          );
        if (!/^[A-Za-z0-9._-]{3,80}$/.test(values.notice_no))
          throw new Error("공고번호를 확인하세요.");
        if (values.notice_text.trim().length < 20)
          throw new Error(
            "참가조건·규격 등이 포함된 공고문을 20자 이상 입력하세요.",
          );
        for (const key of [
          "published_at",
          "application_deadline",
          "bid_deadline",
          "delivery_deadline",
        ]) {
          const text = values[key];
          values[key] = text
            ? (text.length === 16 ? text + ":00" : text) + "+09:00"
            : null;
        }
        if (
          values.application_deadline &&
          values.bid_deadline &&
          Date.parse(values.application_deadline) >
            Date.parse(values.bid_deadline)
        )
          throw new Error("참가신청 마감과 투찰 마감 순서를 확인하세요.");
        for (const key of ["quantity", "estimate_ex_vat"]) {
          values[key] = values[key] || null;
        }
        const packet = JSON.stringify(
          { version: 1, notices: [values] },
          null,
          2,
        );
        if (new TextEncoder().encode(packet).length > 60000)
          throw new Error(
            "반입 자료가 60KB를 초과했습니다. 공고문을 나눠 준비하세요.",
          );
        $("#intake-packet").value = packet;
        $("#intake-ready").hidden = false;
      } catch (error) {
        root.textContent = error.message;
      }
    };
  if ($("#copy-intake"))
    $("#copy-intake").onclick = async () => {
      const area = $("#intake-packet");
      try {
        await navigator.clipboard.writeText(area.value);
        $("#copy-intake").textContent = "복사했습니다";
      } catch {
        area.focus();
        area.select();
        $("#copy-intake").textContent = "선택된 내용을 복사하세요";
      }
    };
  $("#login-form").onsubmit = async (event) => {
    event.preventDefault();
    const b = $("#unlock");
    b.disabled = true;
    b.textContent = "자료 여는 중…";
    try {
      await unlock($("#password").value);
    } catch (error) {
      $("#login-error").textContent = error.message;
    } finally {
      $("#login-status").textContent = "";
      b.disabled = false;
      b.textContent = "검토실 열기 →";
      $("#password").value = "";
    }
  };
  $("#logout").onclick = () => {
    if(historyAbort)historyAbort.abort();historyLoad=null;
    historicalIndex = null;
    snapshot = null;
    password = null;
    selected = null;
    for (const id of [
      "rows",
      "detail",
      "metrics",
      "sources",
      "model",
      "policy",
      "feedback-list",
    ])
      clear($("#" + id));
    if ($("#intake-form")) {
      $("#intake-form").reset();
      $("#intake-packet").value = "";
      $("#intake-error").textContent = "";
      $("#intake-ready").hidden = true;
    }
    $("#feedback-form").reset();$("#feedback-form").hidden=true;
    $("#feedback-packet").value="";$("#feedback-ready").hidden=true;$("#feedback-save").removeAttribute("href");$("#feedback-title").textContent="";
    $("#feedback-error").textContent="";
    $("#snapshot-time").textContent = "";
    $("#freshness").textContent = "";
    $("#app").hidden = true;
    $("#login").hidden = false;
    $("#login").style.display = "";
    $("#password").focus();
  };
  $("#reload").onclick = async () => {
    const b = $("#reload");
    b.disabled = true;
    try {
      await unlock(password, true);
    } catch (error) {
      $("#freshness").textContent =
        error.message + " · 기존 자료를 표시합니다.";
    } finally {
      b.disabled = false;
    }
  };
  $("#search").oninput = () => {
    offset = 0;
    renderRows();
  };
  $("#source-filter").onchange = () => { offset = 0; renderRows(); };
  $("#stage").onchange = () => {
    offset = 0;
    renderRows();
  };
  $("#previous").onclick = () => {
    offset = Math.max(0, offset - 30);
    renderRows();
  };
  $("#next").onclick = () => {
    offset += 30;
    renderRows();
  };
  document.querySelectorAll("nav button").forEach(
    (b) =>
      (b.onclick = () => {
        const tab = b.dataset.tab;
        for (const name of ["work", "feedback", "sources", "model", "policy", "intake"]) {
          const section = $("#" + name);
          if (section) section.hidden = name !== tab;
        }
        document
          .querySelectorAll("nav button")
          .forEach((n) => n.classList.toggle("active", n === b));
        $("#page-title").textContent = {
          work: "오늘의 검토 순서",
          feedback:"우리의 투찰과 실제 결과",
          sources: "수집 상태",
          model: "낙찰가격 · ML",
          policy: "사업 기준",
          intake: "한전 공고 반입",
        }[tab];
      }),
  );
  const outcomeNames = {submitted:"결과 대기",won:"낙찰 성공",lost:"미낙찰",invalid:"무효·자격 탈락",cancelled:"공고 취소",no_award:"유찰",withdrawn:"철회"};
  const localTime = (value) => new Date(Date.parse(value || new Date().toISOString()) + 9*3600000).toISOString().slice(0,16);
  const isoKst = (value) => value ? value + ":00+09:00" : null;
  function switchTab(name) { document.querySelector(`nav [data-tab="${name}"]`).click(); }
  function resultFields() {
    const f=$("#feedback-form"), result=["won","lost"].includes(f.elements.status.value);
    $("#feedback-result").hidden=!result;$("#feedback-result").disabled=!result;
    for(const key of ["winning_amount","awarded_at","result_source"])f.elements[key].required=result && f.elements.result_verified.checked;
    $("#feedback-tax").hidden=f.elements.vat_basis.value!=="included";
    f.elements.vat_rate.required=f.elements.vat_basis.value==="included";
    f.elements.vat_rate.disabled=f.elements.vat_basis.value!=="included";
  }
  function chooseFeedback(id, old=null) {
    const d=snapshot.details[id];if(!d)return;
    const f=$("#feedback-form");f.reset();f.hidden=false;
    $("#feedback-title").textContent=d.title;
    for(const key of ["opportunity_id","revision"])f.elements[key].value=key==="opportunity_id"?id:(old?.revision||d.revision);
    f.elements.submitted_at.value=localTime(old?.submitted_at);
    for(const key of ["own_bid_amount","status","vat_basis","vat_rate","winning_amount","result_source","winner_name","reviewer","reason"])
      if(old?.[key]!=null)f.elements[key].value=old[key];
    for(const key of ["product_key","manufacturer_model","quantity","unit","estimate_ex_vat"])f.elements[key].value=d[key]||"";
    if(old?.awarded_at)f.elements.awarded_at.value=localTime(old.awarded_at);
    f.elements.result_verified.checked=old?.result_verified===true;
    if(old?.result_candidate && !old.winning_amount){
      f.elements.winning_amount.value=old.result_candidate.award_amount_raw||"";
      if(old.result_candidate.awarded_at)f.elements.awarded_at.value=localTime(old.result_candidate.awarded_at);
    }
    $("#feedback-ready").hidden=true;$("#feedback-error").textContent="";resultFields();switchTab("feedback");
  }
  function renderFeedback() {
    const root=clear($("#feedback-list"));
    for(const r of snapshot.outcomes||[]) {
      const card=el("div",null,"data-card"),d=snapshot.details[r.opportunity_id];
      card.append(el("strong",d?.title||r.snapshot?.title||r.opportunity_id),el("p",`${outcomeNames[r.status]||r.status} · 우리 투찰 ${money(r.own_bid_amount)} · 실제 낙찰 ${money(r.winning_amount)}`));
      if(r.result_candidate && !r.result_verified)card.append(el("p","공식 수집자료에서 결과를 찾았습니다. 금액·당사 낙찰 여부를 확인하세요.","notice"));
      const b=el("button","결과 입력·수정");b.onclick=()=>chooseFeedback(r.opportunity_id,r);card.append(b);root.append(card);
    }
    if(!root.childElementCount)root.append(el("p","아직 투찰 기록이 없습니다. 공고를 선택해 ‘투찰 기록’을 눌러 시작하세요.","muted"));
  }
  function prepareSave(packet, label) {
    const body=JSON.stringify(packet,null,2);
    if(new TextEncoder().encode(body).length>15000)throw new Error("기록이 너무 깁니다. 메모 길이를 줄여주세요.");
    const url=new URL("https://github.com/JustinSJung/thelaon-bid-assistant/issues/new");
    url.searchParams.set("title","[더라온 기록] "+label);url.searchParams.set("body",body);
    $("#feedback-packet").value=body;$("#feedback-save").href=url.href;$("#feedback-ready").hidden=false;
    switchTab("feedback");
    window.open(url.href,"_blank","noopener,noreferrer");
  }
  $("#feedback-form").elements.result_verified.onchange=resultFields;
  $("#feedback-form").elements.status.onchange=resultFields;
  $("#feedback-form").elements.vat_basis.onchange=resultFields;
  $("#feedback-form").onsubmit=(event)=>{
    event.preventDefault();$("#feedback-error").textContent="";
    try {
      const f=$("#feedback-form"),v=Object.fromEntries(new FormData(f));
      const r={opportunity_id:v.opportunity_id,revision:v.revision,own_bid_amount:v.own_bid_amount,
        submitted_at:isoKst(v.submitted_at),status:v.status,vat_basis:v.vat_basis,vat_rate:v.vat_rate||null,
        reviewer:v.reviewer,result_verified:f.elements.result_verified.checked && ["won","lost"].includes(v.status),reason:v.reason,winner_name:v.winner_name};
      if(Date.parse(r.submitted_at)>Date.now())throw new Error("미래의 투찰은 실제 기록으로 저장할 수 없습니다.");
      if(["won","lost"].includes(v.status)) {
        const u=v.result_source ? new URL(v.result_source) : null;
        if(u && (u.protocol!=="https:"||u.username||u.password||u.hash||/token|secret|password|cookie|session|apikey/i.test(u.search+u.pathname)))throw new Error("인증정보 없는 공개 HTTPS 결과 주소를 입력하세요.");
        if(v.status==="won" && v.winning_amount && Number(v.winning_amount)!==Number(v.own_bid_amount))throw new Error("낙찰금액과 우리 투찰금액을 대조하세요.");
        Object.assign(r,{winning_amount:v.winning_amount,awarded_at:isoKst(v.awarded_at),result_source:v.result_source});
      }
      if(f.elements.fields_verified.checked) {
        if(!v.reviewer||!v.product_key||!v.unit||!(Number(v.quantity)>0)||!(Number(v.estimate_ex_vat)>0))throw new Error("규격 확인에는 담당자·식별값·수량·단위·추정가격이 필요합니다.");
        r.case_fields=Object.fromEntries(["product_key","manufacturer_model","quantity","unit","estimate_ex_vat"].map(k=>[k,v[k]]));r.fields_verified=true;
      }
      prepareSave({version:1,record:r},outcomeNames[r.status]);
    } catch(e){$("#feedback-error").textContent=e.message;}
  };
  let historicalIndex=null,historyLoad=null,historyAbort=null;
  async function loadHistory() {
    if(!snapshot || snapshot.history_index)return;
    if(!historyLoad){
      const active=snapshot,secret=password;historyAbort=new AbortController();
      historyLoad=(async()=>{
        if(active.history_asset!=="history.enc.json")throw new Error("과거 자료 형식을 확인하세요.");
        const response=await fetch("./history.enc.json",{cache:"no-cache",credentials:"omit",referrerPolicy:"no-referrer",signal:historyAbort.signal});
        if(!response.ok)throw new Error("과거 자료를 불러오지 못했습니다.");
        const bytes=await response.arrayBuffer();
        const digest=[...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))].map(b=>b.toString(16).padStart(2,"0")).join("");
        if(digest!==active.history_sha256)throw new Error("자료가 갱신됐습니다. 최신 자료 확인을 눌러주세요.");
        const data=await decryptData(JSON.parse(new TextDecoder().decode(bytes)),secret);
        if(data.version!==1||!Array.isArray(data.rows))throw new Error("과거 자료 형식 확인 필요");
        if(snapshot===active){active.history_index=data.rows;historicalIndex=null;}
      })();
      historyLoad.catch(()=>{if(snapshot===active)historyLoad=null;});
    }
    await historyLoad;
  }
  const stopWords=new Set(["구매","물품","입찰","공고","납품","제조","설치","공급","계약","긴급","재공고","구입","purchase","supply"]);
  const words=(s)=>new Set(String(s||"").replace(/^\[[^\]]+\]/,"").normalize("NFKC").toLowerCase().replace(/[^a-z0-9가-힣]+/g," ").trim().split(/\s+/).filter(w=>w&&!stopWords.has(w)));
  const tri=(s)=>{const t=[...words(s)].sort().join("");return new Set(Array.from({length:Math.max(0,t.length-2)},(_,i)=>t.slice(i,i+3)));};
  const overlap=(a,b)=>{let same=0;for(const v of a)if(b.has(v))same++;return same/Math.max(1,a.size+b.size-same);};
  function pastPrices(d) {
    if(!historicalIndex)historicalIndex=(snapshot.history_index||[]).map(r=>({r,w:words(r.title),g:tri(r.title)}));
    const w=words(d.title),g=tri(d.title),seen=new Set(),matches=[];
    for(const item of historicalIndex) {
      const r=item.r,key=r.tender_id||r.id;if(!key||key===d.id||seen.has(key))continue;
      let score=Math.max(overlap(w,item.w),overlap(g,item.g));
      const exact=d.product_key&&d.product_key===r.product_key;
      if(exact)score=1;
      else if(d.manufacturer_model&&String(d.manufacturer_model).toLowerCase()===String(r.manufacturer_model).toLowerCase())score=.98;
      if(score<.18||r.awarded_at&&Date.parse(r.awarded_at)>Date.now())continue;
      seen.add(key);
      const qualified=!!(exact&&r.reviewed&&r.price_basis_verified&&r.source&&d.unit&&d.unit===r.unit&&Number(d.quantity)>0&&Number(d.quantity)===Number(r.quantity)&&d.contract_scope===r.contract_scope&&d.contract_scope==="fixed_total"&&d.money_basis===r.money_basis&&d.money_basis==="KRW_EX_VAT_CONTRACT_TOTAL"&&Date.now()-Date.parse(r.awarded_at)<=730*86400000&&Date.parse(r.label_available_at)<=Date.now()&&Number.isSafeInteger(Number(r.award_amount_ex_vat))&&Number(r.award_amount_ex_vat)>0);
      matches.push({...r,score,qualified});
    }
    matches.sort((a,b)=>Number(b.qualified)-Number(a.qualified)||b.score-a.score);
    return matches;
  }
  async function renderHistory(parent,d) {
    const root=el("section");root.dataset.historyState="loading";parent.append(root);
    root.append(el("h3","비슷한 품목의 과거 낙찰가격"));
    const loading=el("p","과거 낙찰자료를 불러오는 중…","muted");root.append(loading);
    try{await loadHistory();}catch(e){if(snapshot&&selected===d.id)loading.textContent=e.message;return;}
    if(!snapshot||selected!==d.id||!root.isConnected)return;loading.remove();root.dataset.historyState="ready";
    const rows=pastPrices(d),values=rows.filter(r=>r.qualified).map(r=>Number(r.award_amount_ex_vat)).sort((a,b)=>a-b);
    if(values.length>=3){const mid=Math.floor(values.length/2),median=values.length%2?values[mid]:values[mid-1]/2+values[mid]/2;root.append(el("p",`동일 규격·수량 ${values.length}건의 과거 중앙값 ${money(median)} (부가세 별도). ML 예측·최종 투찰가는 별도입니다.`,"notice"));}
    if(!rows.length)root.append(el("p","연결할 만한 과거 품목을 찾지 못했습니다.","muted"));
    for(const r of rows.slice(0,5)) {
      const box=el("details");box.append(el("summary",`${r.title||"공고명 미확인"} · ${Number(r.award_amount_ex_vat||r.award_amount_raw)>0?money(r.award_amount_ex_vat||r.award_amount_raw):"금액 미확인"}`));
      box.append(el("p",r.qualified?"동일 규격·동일 수량·세금 기준 확인된 과거 사례":"제목·모델이 비슷한 참고 사례. 규격·수량·단가/총액·세금 대조 필요"),el("p",`기관 ${r.institution||"미확인"} · 낙찰 ${date(r.awarded_at)} · 수량 ${r.quantity||"미확인"} ${r.unit||""}`));
      if(r.feature_source)box.append(link(r.feature_source,"연결된 공고 원문"));
      if(r.source)box.append(link(r.source,r.source.includes("data.go.kr")?"공식 수집 API 안내":"개찰결과 출처"));root.append(box);
    }
  }
  function renderSpecification(root,d) {
    const box=el("details",null,"spec-fields");box.append(el("summary","비교할 제품·규격 확인"),el("p","투찰 전에도 모델을 등록할 수 있습니다. 같은 규격 식별값을 쓰면 과거 낙찰가와 더 정확하게 연결됩니다.","muted"));
    const inputs={};
    for(const [key,label,type] of [["product_key","동일 규격 식별값 (제조사/모델/주요 규격)","text"],["manufacturer_model","모델","text"],["quantity","수량","number"],["unit","단위","text"],["estimate_ex_vat","공고 추정가격 총액 (부가세 별도)","number"],["reviewer","확인한 사람","text"]]) {
      const wrap=el("label",label),input=el("input");input.type=type;input.value=d[key]||"";
      if(type==="number"){input.min="0";input.step="any";}else input.maxLength=300;
      inputs[key]=input;wrap.append(input);box.append(wrap);
    }
    const label=el("label"),verified=el("input");verified.type="checkbox";label.append(verified,document.createTextNode(" 원문에서 규격·수량·단위·총액·부가세 별도 기준을 대조했습니다"));box.append(label);
    const error=el("p"),button=el("button","확인한 규격 저장");button.onclick=()=>{try{
      const value={opportunity_id:d.id,revision:d.revision,verified:verified.checked};
      for(const [k,input]of Object.entries(inputs))value[k]=input.value;
      if(!value.reviewer||!value.product_key&&!value.manufacturer_model)throw new Error("모델 또는 규격 식별값과 확인한 사람을 입력하세요.");
      if(value.verified&&(!value.product_key||!value.unit||!(Number(value.quantity)>0)||!(Number(value.estimate_ex_vat)>0)))throw new Error("확정하려면 규격·수량·단위·추정가격을 모두 확인하세요.");
      prepareSave({version:1,specification:value},"품목 규격 확인");
    }catch(e){error.textContent=e.message;}};box.append(button,error);root.append(box);
  }
  function renderMarketDiscovery(root,d) {
    root.append(el("h3","국내·해외 시장가격"));
    for(const p of d.market?.observations||[]) {
      const box=el("p");box.append(el("strong",`${p.unit_price} ${p.currency} · ${p.model||p.title||"모델 미확인"}`),el("small",`관찰 판매가 · 세금·단위·공급 가능 여부 미검토 · ${date(p.checked_at)}`),link(p.source,"판매 페이지"));root.append(box);
    }
    for(const run of d.market_search||[])for(const region of run.results||[])for(const source of region.sources||[]){const p=el("p");p.append(el("small",region.region+" 검색 후보 · 가격·규격 확인 필요"),link(source.url,source.title||"검색 출처"));root.append(p);}
    const details=el("details");details.append(el("summary","국내·해외 가격 찾기와 상품 주소 등록"),el("p","검색 바로가기는 검색 결과 자동수집이 아닙니다. 찾은 공개 상품 주소는 등록 후 갱신하며, 수집 제한·가격 미표시는 미확인으로 표시합니다.","muted"));
    const term=d.manufacturer_model||String(d.title||"").replace(/^\[[^\]]+\]/,"");
    for(const [name,base,key,q] of [["네이버 국내","https://search.naver.com/search.naver","query",term+" 가격"],["Google 국내·해외","https://www.google.com/search","q",term+" price"],["중국 공급처","https://www.google.com/search","q",term+" China manufacturer wholesale price"],["대만 공급처","https://www.google.com/search","q",term+" Taiwan manufacturer price"],["미국 공급처","https://www.google.com/search","q",term+" USA distributor price"]]){const p=el("p"),u=new URL(base);u.searchParams.set(key,q);p.append(link(u.href,name));details.append(p);}
    const input=el("input");input.type="url";input.placeholder="확인한 공개 상품 페이지 https://…";input.setAttribute("aria-label","시장가격 상품 주소");
    const b=el("button","이 상품 주소를 비교자료로 등록");b.onclick=()=>{try{const u=new URL(input.value);if(u.protocol!=="https:"||u.username||u.password||u.hash)throw new Error("공개 HTTPS 상품 주소를 입력하세요.");prepareSave({version:1,market:{opportunity_id:d.id,source_url:u.href}},"시장가격 자료");}catch(e){alert(e.message);}};
    details.append(input,b);root.append(details);
  }

  // Download only public ciphertext while the user enters their password.
  encryptedSnapshot().catch(() => {});
})();
