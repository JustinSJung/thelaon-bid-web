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
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
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
  async function unlock(secret) {
    const response = await fetch("./snapshot.enc.json?t=" + Date.now(), {
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok)
      throw new Error("최신 분석 자료가 아직 준비되지 않았습니다.");
    const e = await response.json();
    if (e.format !== "thelaon:web:v1" || e.iterations !== 600000)
      throw new Error("자료 형식을 확인하세요.");
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
      const text = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: b64(e.nonce),
          additionalData: new TextEncoder().encode("thelaon:web:v1"),
        },
        key,
        b64(e.ciphertext),
      );
      data = JSON.parse(new TextDecoder().decode(text));
    } catch {
      throw new Error("접속 암호가 다르거나 자료가 변경됐습니다.");
    }
    if (data.version !== 1 || !Array.isArray(data.worklist?.rows))
      throw new Error("검토 자료 형식이 올바르지 않습니다.");
    snapshot = data;
    password = secret;
    $("#password").value = "";
    $("#login-error").textContent = "";
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
      if (expired.length) {
        row.stage = "excluded";
        row.stage_title = "마감·제외";
        row.reason = expired
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
      "분석 자료 생성 " + date(snapshot.generated_at) + " · 읽기 전용";
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
    if (selected) showDetail(selected);
  }
  function renderRows() {
    if (!snapshot) return;
    const search = $("#search").value.toLocaleLowerCase(),
      stage = $("#stage").value;
    const rows = currentRows().filter(
      (r) =>
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
            date(row.bid_deadline),
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
      ["투찰 마감", date(row.bid_deadline)],
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
      b.disabled = false;
      b.textContent = "검토실 열기 →";
      $("#password").value = "";
    }
  };
  $("#logout").onclick = () => {
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
    ])
      clear($("#" + id));
    if ($("#intake-form")) {
      $("#intake-form").reset();
      $("#intake-packet").value = "";
      $("#intake-error").textContent = "";
      $("#intake-ready").hidden = true;
    }
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
      await unlock(password);
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
        for (const name of ["work", "sources", "model", "policy", "intake"]) {
          const section = $("#" + name);
          if (section) section.hidden = name !== tab;
        }
        document
          .querySelectorAll("nav button")
          .forEach((n) => n.classList.toggle("active", n === b));
        $("#page-title").textContent = {
          work: "오늘의 검토 순서",
          sources: "수집 상태",
          model: "낙찰가격 · ML",
          policy: "사업 기준",
          intake: "한전 공고 반입",
        }[tab];
      }),
  );
})();
