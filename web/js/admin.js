const apiBase = "/api";

function getAuthToken() {
  return localStorage.getItem("winmonitor_token");
}

function getUserName() {
  return localStorage.getItem("winmonitor_user") || "unknown";
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
    showPageMessage("网络连接异常，请稍后重试。");
    return null;
  }
}

function showPageMessage(message) {
  const banner = document.querySelector("#pageMessage");
  if (!banner) {
    return;
  }
  banner.textContent = message || "";
  banner.style.display = message ? "block" : "none";
}

window.addEventListener("error", (event) => {
  showPageMessage("页面错误：" + event.message);
});
window.addEventListener("unhandledrejection", (event) => {
  showPageMessage("Promise 未处理错误：" + (event.reason?.message || event.reason));
});

function renderUserTable(users) {
  const container = document.querySelector("#userList");
  if (!container) {
    return;
  }
  if (!users || users.length === 0) {
    container.innerHTML = "当前没有用户数据。";
    return;
  }

  container.innerHTML = `
    <table class="user-table">
      <thead>
        <tr>
          <th>用户名</th>
          <th>角色</th>
          <th>在线状态</th>
          <th>最后活动</th>
        </tr>
      </thead>
      <tbody>
        ${users
          .map(
            (user) => `
              <tr>
                <td>${user.username}</td>
                <td>${user.is_admin ? "管理员" : "普通用户"}</td>
                <td><span class="status-badge ${user.online ? "online" : "offline"}">${user.online ? "在线" : "离线"}</span></td>
                <td>${user.last_seen || "暂无"}</td>
              </tr>
            `,
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function renderRequests(requests) {
  const container = document.querySelector("#adminRequests");
  if (!container) {
    return;
  }
  if (!requests) {
    container.innerHTML = "无法加载请求。";
    return;
  }
  if (requests.length === 0) {
    container.innerHTML = "当前没有待审批请求。";
    return;
  }
  container.innerHTML = requests
    .map(
      (req) => `
        <div class="request-item">
          <h3>${req.username} - ${getRequestTypeLabel(req.request_type)}</h3>
          <p>${req.details || "无附加信息"}</p>
          <small>提交时间: ${req.submitted_at}</small>
          <div class="request-actions">
            <button onclick="reviewRequest(${req.id}, 'approve')">批准</button>
            <button onclick="reviewRequest(${req.id}, 'deny')">拒绝</button>
          </div>
        </div>
      `,
    )
    .join("");
}

function getRequestTypeLabel(type) {
  const labels = {
    "forgot_password": "密码重置申请",
    "password_change": "密码修改申请",
    "delete_account": "删除账号申请",
    "register": "注册申请"
  };
  return labels[type] || type;
}

async function reviewRequest(id, action) {
  const result = await fetchApi(`/admin/requests/${id}/review`, {
    method: "POST",
    body: JSON.stringify({ action }),
  });
  if (result && result.success) {
    await refreshAdmin();
  } else {
    alert(result?.message || "审批失败。");
  }
}

async function refreshAdmin() {
  const userName = getUserName();
  document.querySelector("#userName").textContent = userName;
  document.querySelector("#userRole").textContent = "管理员";

  const users = await fetchApi("/admin/users");
  if (users && users.success) {
    showPageMessage("");
    renderUserTable(users.users);
  } else {
    showPageMessage("无法加载用户列表，请检查登录状态或网络。");
    const userList = document.querySelector("#userList");
    if (userList) {
      userList.textContent = "无法加载用户列表。";
    }
  }

  const requests = await fetchApi("/admin/requests");
  if (requests && requests.success) {
    renderRequests(requests.requests);
  } else {
    document.querySelector("#adminRequests").textContent = "无法加载审批请求。";
  }

  await loadAuditLogs();
}

async function loadAuditLogs() {
  const container = document.querySelector("#auditLogs");
  if (!container) {
    return;
  }

  const result = await fetchApi("/logs?limit=100");
  if (!result || !result.success) {
    container.innerHTML = "无法加载审计日志。";
    return;
  }

  const logs = result.logs || [];
  const userChangeLogs = logs.filter(log => log.category === "user");
  
  if (userChangeLogs.length === 0) {
    container.innerHTML = "暂无用户变更日志。";
    return;
  }

  container.innerHTML = `
    <table class="audit-table">
      <thead>
        <tr>
          <th>时间</th>
          <th>用户</th>
          <th>类型</th>
          <th>标题</th>
          <th>级别</th>
        </tr>
      </thead>
      <tbody>
        ${userChangeLogs.map(log => `
          <tr>
            <td>${log.created_at}</td>
            <td>${log.username || "system"}</td>
            <td>${log.category_cn || log.category}</td>
            <td>${log.title}</td>
            <td><span class="severity-badge ${log.severity}">${getSeverityLabel(log.severity)}</span></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function getSeverityLabel(severity) {
  const labels = {
    "critical": "严重",
    "warning": "警告",
    "info": "信息"
  };
  return labels[severity] || severity;
}

document.addEventListener("DOMContentLoaded", () => {
  const token = getAuthToken();
  const isAdmin = localStorage.getItem("winmonitor_is_admin") === "true";
  if (!token || !isAdmin) {
    window.location.href = "/login";
    return;
  }
  const logoutButton = document.querySelector("#logoutButton");
  if (logoutButton) {
    logoutButton.addEventListener("click", logout);
  }
  const refreshButton = document.querySelector("#refreshButton");
  if (refreshButton) {
    refreshButton.addEventListener("click", refreshAdmin);
  }
  refreshAdmin();
});
