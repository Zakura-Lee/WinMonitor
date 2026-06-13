const apiBase = "/api";

function isUsernameValid(username) {
  return username.length >= 3 && username.length <= 32 && /^[A-Za-z0-9_.-]+$/.test(username);
}

function isPasswordStrong(password) {
  return password.length >= 8 && /[A-Za-z]/.test(password) && /\d/.test(password);
}

async function submitLogin(event) {
  event.preventDefault();
  const username = document.querySelector("#username").value.trim();
  const password = document.querySelector("#password").value;
  const messageEl = document.querySelector("#message");

  const user_type = document.querySelector("#user_type").value;
  let payload = null;
  try {
    const response = await fetch(`${apiBase}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, user_type }),
    });
    payload = await response.json().catch(() => null);
  } catch (err) {
    console.error("登录请求失败：", err);
    messageEl.textContent = "网络请求失败，请检查服务器连接。";
    return;
  }
  if (!payload || !payload.success) {
    messageEl.textContent = payload?.message || "登录失败";
    return;
  }

  localStorage.setItem("winmonitor_token", payload.token);
  localStorage.setItem("winmonitor_user", payload.username);
  localStorage.setItem("winmonitor_is_admin", payload.is_admin);
  localStorage.setItem("winmonitor_password_reset", payload.password_reset ? "true" : "false");
  window.location.href = "/menu";
}

async function validateTokenAndRedirect() {
  const token = localStorage.getItem("winmonitor_token");
  if (!token) {
    return false;
  }
  try {
    const resp = await fetch(`${apiBase}/user/me`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    if (resp.status === 401 || resp.status === 403) {
      localStorage.removeItem("winmonitor_token");
      localStorage.removeItem("winmonitor_user");
      localStorage.removeItem("winmonitor_is_admin");
      return false;
    }
    const data = await resp.json().catch(() => null);
    if (data?.success) {
      window.location.href = "/menu";
      return true;
    }
  } catch (err) {
    console.error("Token 验证失败：", err);
  }
  localStorage.removeItem("winmonitor_token");
  localStorage.removeItem("winmonitor_user");
  localStorage.removeItem("winmonitor_is_admin");
  return false;
}

async function submitRegister(event) {
  event.preventDefault();
  const username = document.querySelector("#username").value.trim();
  const password = document.querySelector("#password").value;
  const confirmPassword = document.querySelector("#confirm_password").value;
  const messageEl = document.querySelector("#message");

  if (password !== confirmPassword) {
    messageEl.textContent = "两次密码不一致，请重新输入。";
    return;
  }
  if (!username || !password) {
    messageEl.textContent = "用户名和密码不能为空。";
    return;
  }
  if (!isUsernameValid(username)) {
    messageEl.textContent = "用户名长度 3-32 位，仅支持字母、数字、下划线、点和短划线。";
    return;
  }

  const user_type = document.querySelector("#user_type").value;
  let payload = null;
  try {
    const response = await fetch(`${apiBase}/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, confirm_password: confirmPassword, user_type }),
    });
    payload = await response.json().catch(() => null);
  } catch (err) {
    console.error("注册请求失败：", err);
    messageEl.textContent = "网络请求失败，请检查服务器连接。";
    return;
  }
  if (!payload || !payload.success) {
    messageEl.textContent = payload?.message || "注册失败";
    return;
  }

  messageEl.textContent = "注册成功，正在跳转登录页面...";
  setTimeout(() => {
    window.location.href = "/login";
  }, 1200);
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

async function submitForgotPassword() {
  const username = document.querySelector("#username").value.trim();
  const messageEl = document.querySelector("#message");

  if (!username) {
    messageEl.textContent = "请输入用户名。";
    return;
  }

  let payload = null;
  try {
    const response = await fetch(`${apiBase}/forgot-password`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username }),
    });
    payload = await response.json().catch(() => null);
  } catch (err) {
    console.error("忘记密码请求失败：", err);
    messageEl.textContent = "网络请求失败，请检查服务器连接。";
    return;
  }
  if (!payload || !payload.success) {
    messageEl.textContent = payload?.message || "操作失败";
    return;
  }

  messageEl.textContent = payload.message;
}

document.addEventListener("DOMContentLoaded", async () => {
  await validateTokenAndRedirect();

  const loginForm = document.querySelector("#loginForm");
  const registerForm = document.querySelector("#registerForm");
  const exitButton = document.querySelector("#exitSystemButton");
  const forgotPasswordLink = document.querySelector("#forgotPasswordLink");

  if (loginForm) {
    loginForm.addEventListener("submit", submitLogin);
  }
  if (registerForm) {
    registerForm.addEventListener("submit", submitRegister);
  }
  if (exitButton) {
    exitButton.addEventListener("click", exitSystem);
  }
  if (forgotPasswordLink) {
    forgotPasswordLink.addEventListener("click", (e) => {
      e.preventDefault();
      submitForgotPassword();
    });
  }
});
