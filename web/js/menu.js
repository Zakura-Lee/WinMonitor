const apiBase = "/api";

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

async function exitSystem() {
  try {
    await fetch(`${apiBase}/system/exit`, { method: "POST" });
  } catch (err) {
    console.error("退出系统请求失败：", err);
  }
  window.open("", "_self");
  window.close();
  setTimeout(() => {
    window.location.href = "/closed.html";
  }, 300);
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
    return null;
  }
}

function showPageMessage(message) {
  const banner = document.querySelector("#pageMessage");
  if (!banner) {
    return;
  }
  banner.textContent = message;
  banner.style.display = message ? "block" : "none";
}

async function initPage() {
  const userNameEl = document.querySelector("#userName");
  const userRoleEl = document.querySelector("#userRole");
  const userResponse = await fetchApi("/user/me");
  if (userResponse && userResponse.success) {
    const username = userResponse.username;
    const isAdmin = userResponse.is_admin;
    if (userNameEl) {
      userNameEl.textContent = username;
    }
    if (userRoleEl) {
      userRoleEl.textContent = isAdmin ? "管理员" : "普通用户";
    }
    localStorage.setItem("winmonitor_user", userResponse.username);
    localStorage.setItem("winmonitor_is_admin", userResponse.is_admin);
  } else {
    localStorage.removeItem("winmonitor_token");
    localStorage.removeItem("winmonitor_user");
    localStorage.removeItem("winmonitor_is_admin");
    showPageMessage("登录信息无效，请重新登录。");
    setTimeout(() => {
      window.location.href = "/login";
    }, 1200);
    return;
  }
  const logoutBtn = document.querySelector("#logoutButton");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", logout);
  }

  const exitBtn = document.querySelector("#exitSystemButton");
  if (exitBtn) {
    exitBtn.addEventListener("click", exitSystem);
  }

  const adminCard = document.querySelector("#adminPanelCard");
  if (adminCard) {
    adminCard.style.display = getAdminFlag() ? "block" : "none";
  }

  const message = localStorage.getItem("winmonitor_menu_message");
  if (message) {
    showPageMessage(message);
    localStorage.removeItem("winmonitor_menu_message");
  }

  const passwordResetAlert = document.querySelector("#passwordResetAlert");
  const passwordReset = localStorage.getItem("winmonitor_password_reset");
  if (passwordResetAlert && passwordReset === "true") {
    passwordResetAlert.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (!getAuthToken()) {
    window.location.href = "/login";
    return;
  }
  initPage();
});
