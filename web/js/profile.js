const apiBase = "/api";

function isUsernameValid(username) {
  return username.length >= 3 && username.length <= 32 && /^[A-Za-z0-9_.-]+$/.test(username);
}

function isPasswordStrong(password) {
  return password.length >= 8 && /[A-Za-z]/.test(password) && /\d/.test(password);
}

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
    showPageMessage("网络连接异常，请稍后重试。");
    return null;
  }
}

function setMessage(selector, text) {
  const el = document.querySelector(selector);
  if (el) {
    el.textContent = text;
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

async function loadProfile() {
  const response = await fetchApi("/user/me");
  if (!response || !response.success) {
    showPageMessage("无法加载用户信息，请重新登录。");
    localStorage.removeItem("winmonitor_token");
    localStorage.removeItem("winmonitor_user");
    localStorage.removeItem("winmonitor_is_admin");
    setTimeout(() => {
      window.location.href = "/login";
    }, 1200);
    return;
  }
  document.querySelector("#userName").textContent = response.username;
  document.querySelector("#userRole").textContent = response.is_admin ? "管理员" : "普通用户";
}

async function submitUsernameChange(event) {
  event.preventDefault();
  const newUsername = document.querySelector("#new_username").value.trim();
  const currentPassword = document.querySelector("#current_password_for_username").value;
  if (!newUsername) {
    setMessage("#usernameMessage", "请输入新用户名。");
    return;
  }
  if (!isUsernameValid(newUsername)) {
    setMessage("#usernameMessage", "用户名长度 3-32 位，仅支持字母、数字、下划线、点和短横线。");
    return;
  }
  const response = await fetchApi("/user/change-username", {
    method: "POST",
    body: JSON.stringify({ new_username: newUsername, current_password: currentPassword }),
  });
  if (!response || !response.success) {
    setMessage("#usernameMessage", response?.message || "修改用户名失败。");
    return;
  }
  if (response.token) {
    localStorage.setItem("winmonitor_token", response.token);
  }
  localStorage.setItem("winmonitor_user", newUsername);
  setMessage("#usernameMessage", "用户名修改成功。已更新为新用户名。");
  loadProfile();
}

async function submitPasswordChange(event) {
  event.preventDefault();
  const currentPassword = document.querySelector("#current_password").value;
  const newPassword = document.querySelector("#new_password").value;
  const confirmPassword = document.querySelector("#confirm_password").value;
  if (!currentPassword || !newPassword || !confirmPassword) {
    setMessage("#passwordMessage", "请填写所有密码字段。");
    return;
  }
  if (newPassword !== confirmPassword) {
    setMessage("#passwordMessage", "两次新密码输入不一致，请重新输入。");
    return;
  }
  if (newPassword === currentPassword) {
    setMessage("#passwordMessage", "新密码不能与当前密码相同，请重新设置。");
    return;
  }
  if (!isPasswordStrong(newPassword)) {
    setMessage("#passwordMessage", "密码至少 8 位，必须包含字母和数字。");
    return;
  }

  const response = await fetchApi("/user/change-password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  if (!response || !response.success) {
    setMessage("#passwordMessage", response?.message || "修改密码失败。");
    return;
  }
  localStorage.removeItem("winmonitor_password_reset");
  setMessage("#passwordMessage", "密码已修改成功，请使用新密码登录。即将跳转登录页...");
  setTimeout(() => {
    logout();
  }, 1500);
}

function initPage() {
  const logoutBtn = document.querySelector("#logoutButton");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", logout);
  }
  const usernameForm = document.querySelector("#usernameForm");
  if (usernameForm) {
    usernameForm.addEventListener("submit", submitUsernameChange);
  }
  const passwordForm = document.querySelector("#passwordForm");
  if (passwordForm) {
    passwordForm.addEventListener("submit", submitPasswordChange);
  }
  const deleteBtn = document.querySelector("#deleteAccountButton");
  if (deleteBtn) {
    deleteBtn.addEventListener("click", deleteAccount);
  }
  loadProfile();
}

async function deleteAccount(event) {
  if (event) {
    event.preventDefault();
  }
  if (!confirm("确认注销当前账号？此操作不可恢复。")) {
    return;
  }
  const response = await fetchApi("/user/delete-account", { method: "POST" });
  if (!response || !response.success) {
    setMessage("#passwordMessage", response?.message || "账号注销失败。请稍后重试。");
    return;
  }
  logout();
}

document.addEventListener("DOMContentLoaded", () => {
  if (!getAuthToken()) {
    window.location.href = "/login";
    return;
  }
  initPage();
});
