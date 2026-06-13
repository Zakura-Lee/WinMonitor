const apiBase = "/api";

// 监控日志类型列表（用于区分监控日志和用户变更日志）
const MONITOR_CATEGORIES = ["file", "process", "network", "registry", "audit", "asset", "monitor"];

function getAuthToken() {
  return localStorage.getItem("winmonitor_token");
}

function getUserName() {
  return localStorage.getItem("winmonitor_user") || "unknown";
}

function getAdminFlag() {
  return localStorage.getItem("winmonitor_is_admin") === "true";
}

function logout() {
  localStorage.removeItem("winmonitor_token");
  localStorage.removeItem("winmonitor_user");
  localStorage.removeItem("winmonitor_is_admin");
  window.location.href = "/login";
}

async function fetchApi(path, options) {
  options = options || {};
  var token = getAuthToken();
  if (!token) {
    logout();
    return null;
  }
  try {
    var response = await fetch(apiBase + path, {
      method: options.method || "GET",
      body: options.body || undefined,
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json"
      }
    });
    if (response.status === 401 || response.status === 403) {
      logout();
      return null;
    }
    return await response.json().catch(function() { return null; });
  } catch (err) {
    console.error("API 请求失败：", err);
    var summaryEl = document.querySelector("#logsSummary");
    if (summaryEl) {
      summaryEl.textContent = "网络连接异常，无法加载日志。";
    }
    return null;
  }
}

function renderLogEntry(entry) {
  const severityClass = `log-${entry.severity}`;
  const severityText = {
    "info": "信息",
    "warning": "警告",
    "critical": "严重",
  }[entry.severity] || entry.severity;
  return `
    <div class="log-entry">
      <div class="log-header">
        <span class="log-time">${entry.created_at}</span>
        <span class="log-level ${severityClass}">${severityText}</span>
      </div>
      <div class="log-meta">
        <span>用户: ${entry.username}</span>
        <span>来源: ${entry.source}</span>
      </div>
      <h3>${entry.title}</h3>
      <p>${entry.message}</p>
    </div>
  `;
}

function renderLogCategory(categoryCn, entries, categoryId) {
  const severityCounts = entries.reduce((summary, entry) => {
    summary[entry.severity] = (summary[entry.severity] || 0) + 1;
    return summary;
  }, {});
  const severitySummary = Object.entries(severityCounts)
    .map(([severity, count]) => {
      const severityText = {
        "info": "信息",
        "warning": "警告",
        "critical": "严重",
      }[severity] || severity;
      return `<span class="log-severity-count">${severityText}: ${count}</span>`;
    })
    .join(" ");
  return `
    <div class="log-category">
      <button type="button" class="log-category-header" data-target="${categoryId}">
        <span>${categoryCn}</span>
        <span>${entries.length} 条</span>
        <span>${severitySummary}</span>
      </button>
      <div id="${categoryId}" class="category-entries" style="display:none; margin-top: 8px;">
        ${entries.map(renderLogEntry).join("")}
      </div>
    </div>
  `;
}

function renderUserCategory(username, entries, categoryId) {
  const severityCounts = entries.reduce((summary, entry) => {
    summary[entry.severity] = (summary[entry.severity] || 0) + 1;
    return summary;
  }, {});
  const severitySummary = Object.entries(severityCounts)
    .map(([severity, count]) => {
      const severityText = {
        "info": "信息",
        "warning": "警告",
        "critical": "严重",
      }[severity] || severity;
      return `<span class="log-severity-count">${severityText}: ${count}</span>`;
    })
    .join(" ");
  return `
    <div class="log-category">
      <button type="button" class="log-category-header" data-target="${categoryId}">
        <span>用户: ${username}</span>
        <span>${entries.length} 条</span>
        <span>${severitySummary}</span>
      </button>
      <div id="${categoryId}" class="category-entries" style="display:none; margin-top: 8px;">
        ${entries.map(renderLogEntry).join("")}
      </div>
    </div>
  `;
}

function attachLogCategoryToggle() {
  document.querySelectorAll(".log-category-header").forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.dataset.target;
      const target = document.getElementById(targetId);
      if (!target) {
        return;
      }
      const show = target.style.display === "none";
      target.style.display = show ? "block" : "none";
      button.classList.toggle("expanded", show);
    });
  });
}

// 普通用户：按日志类型分类展示
function renderNormalUserLogs(logs) {
  const grouped = logs.reduce((result, entry) => {
    const categoryCn = entry.category_cn || entry.category || "其他";
    result[categoryCn] = result[categoryCn] || [];
    result[categoryCn].push(entry);
    return result;
  }, {});

  return Object.entries(grouped)
    .map(([categoryCn, entries]) => {
      const categoryId = `category_${categoryCn.replace(/\W/g, "_")}`;
      return renderLogCategory(categoryCn, entries, categoryId);
    })
    .join("");
}

// 管理员：监控日志按用户名分类收纳在"用户日志"类，其它为"用户变更"
function renderAdminLogs(logs) {
  // 分离监控日志和用户变更日志
  const monitorLogs = logs.filter(entry => MONITOR_CATEGORIES.includes(entry.category));
  const userChangeLogs = logs.filter(entry => !MONITOR_CATEGORIES.includes(entry.category));

  let html = "";

  // 用户日志部分：按用户名分类
  if (monitorLogs.length > 0) {
    const byUser = monitorLogs.reduce((result, entry) => {
      const username = entry.username || "system";
      result[username] = result[username] || [];
      result[username].push(entry);
      return result;
    }, {});

    html += `
      <div class="log-main-category">
        <button type="button" class="log-main-header expanded" data-target="user_logs_section">
          <span>用户日志（监控）</span>
          <span>${monitorLogs.length} 条</span>
        </button>
        <div id="user_logs_section" class="main-category-entries" style="display:block; margin-top: 8px;">
          ${Object.entries(byUser)
            .map(([username, entries]) => {
              const categoryId = `user_${username.replace(/\W/g, "_")}`;
              return renderUserCategory(username, entries, categoryId);
            })
            .join("")}
        </div>
      </div>
    `;
  }

  // 用户变更部分：按类型分类
  if (userChangeLogs.length > 0) {
    const byCategory = userChangeLogs.reduce((result, entry) => {
      const categoryCn = entry.category_cn || entry.category || "其他";
      result[categoryCn] = result[categoryCn] || [];
      result[categoryCn].push(entry);
      return result;
    }, {});

    html += `
      <div class="log-main-category">
        <button type="button" class="log-main-header expanded" data-target="user_change_section">
          <span>用户变更</span>
          <span>${userChangeLogs.length} 条</span>
        </button>
        <div id="user_change_section" class="main-category-entries" style="display:block; margin-top: 8px;">
          ${Object.entries(byCategory)
            .map(([categoryCn, entries]) => {
              const categoryId = `change_${categoryCn.replace(/\W/g, "_")}`;
              return renderLogCategory(categoryCn, entries, categoryId);
            })
            .join("")}
        </div>
      </div>
    `;
  }

  // 如果没有任何日志
  if (logs.length === 0) {
    html = "<p>暂无日志记录。</p>";
  }

  return html;
}

function attachMainCategoryToggle() {
  document.querySelectorAll(".log-main-header").forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.dataset.target;
      const target = document.getElementById(targetId);
      if (!target) {
        return;
      }
      const show = target.style.display === "none";
      target.style.display = show ? "block" : "none";
      button.classList.toggle("expanded", show);
    });
  });
}

async function loadLogs() {
  const logsPanel = document.querySelector("#logEntries");
  const summaryEl = document.querySelector("#logsSummary");
  const isAdmin = getAdminFlag();

  const response = await fetchApi("/logs");
  if (!response || !response.success) {
    logsPanel.innerHTML = "无法加载日志。";
    summaryEl.textContent = "请确认已登录并具有查看日志权限。";
    return;
  }

  const logs = response.logs || [];
  if (logs.length === 0) {
    logsPanel.innerHTML = "当前没有可展示的日志。";
    summaryEl.textContent = isAdmin ? "暂无日志记录。" : "您还没有监控日志记录，启动监控后可查看。";
    return;
  }

  if (isAdmin) {
    logsPanel.innerHTML = renderAdminLogs(logs);
    summaryEl.textContent = `共加载 ${logs.length} 条日志（监控日志 ${logs.filter(e => MONITOR_CATEGORIES.includes(e.category)).length} 条，用户变更 ${logs.filter(e => !MONITOR_CATEGORIES.includes(e.category)).length} 条）。`;
    attachMainCategoryToggle();
  } else {
    logsPanel.innerHTML = renderNormalUserLogs(logs);
    summaryEl.textContent = `共加载 ${logs.length} 条日志，点击日志类型展开详细内容。`;
  }
  attachLogCategoryToggle();
}

function initPage() {
  const userName = getUserName();
  const isAdmin = getAdminFlag();
  document.querySelector("#userName").textContent = userName;
  document.querySelector("#userRole").textContent = isAdmin ? "管理员" : "普通用户";
  document.querySelector("#logoutButton").addEventListener("click", logout);
  document.querySelector("#refreshButton").addEventListener("click", loadLogs);
  loadLogs();
}

document.addEventListener("DOMContentLoaded", () => {
  if (!getAuthToken()) {
    window.location.href = "/login";
    return;
  }
  initPage();
});