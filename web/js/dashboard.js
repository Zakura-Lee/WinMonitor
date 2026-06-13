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

function formatStatusLabel(status) {
  if (status.running) {
    var startedAt = status.started_at ? ("，启动于 " + new Date(status.started_at * 1000).toLocaleString()) : "";
    return "监控正在运行 · 活动线程 " + status.active_threads + startedAt;
  }
  return "监控已停止。";
}

function formatCommandLine(cmdline) {
  if (!cmdline) {
    return "无";
  }
  return cmdline.length > 80 ? cmdline.slice(0, 80) + "..." : cmdline;
}

async function loadMonitorStatus() {
  var statusEl = document.querySelector("#monitorStatus");
  var detailEl = document.querySelector("#detailContent");
  var summaryEl = document.querySelector("#summaryContent");
  
  try {
    var response = await fetchApi("/monitor/status");
    if (!response || !response.success) {
      if (statusEl) statusEl.textContent = "无法获取监控状态。";
      if (detailEl) detailEl.textContent = "请检查网络连接。";
      if (summaryEl) summaryEl.textContent = "无法加载统计信息。";
      return;
    }
    
    if (statusEl) statusEl.textContent = formatStatusLabel(response.status);
    if (detailEl) detailEl.textContent = "活动线程：" + response.status.active_threads;
    if (summaryEl) summaryEl.textContent = response.status.running
      ? "监控已启用，可查看当前进程和最近变化。"
      : "监控未运行，请点击开始监控。";
    
    updateMonitorControlButtons(response.status);
    setMonitoringAnimation(response.status.running);
    
  } catch (e) {
    console.error("加载监控状态失败:", e);
    if (statusEl) statusEl.textContent = "加载失败。";
  }
}

function updateMonitorControlButtons(status) {
  var startBtn = document.querySelector("#startButton");
  var pauseBtn = document.querySelector("#pauseButton");
  var stopBtn = document.querySelector("#stopButton");
  var running = status && status.running;
  
  if (startBtn) startBtn.disabled = running;
  if (pauseBtn) pauseBtn.disabled = !running;
  if (stopBtn) stopBtn.disabled = !running;
}

function setMonitoringAnimation(running) {
  var statusEl = document.querySelector("#monitorStatus");
  if (!statusEl) return;
  statusEl.classList.toggle("running", running);
}

async function loadMonitorProcesses() {
  var changeContainer = document.querySelector("#processChangeList");
  var currentContainer = document.querySelector("#currentProcesses");
  
  try {
    var response = await fetchApi("/monitor/processes");
    if (!response || !response.success) {
      if (changeContainer) changeContainer.innerHTML = "无法加载进程变化。";
      if (currentContainer) currentContainer.innerHTML = "无法加载进程信息。";
      return;
    }
    
    renderProcessChanges(response.process_changes || []);
    renderCurrentProcesses(response.current_processes || []);
    
  } catch (e) {
    console.error("加载进程信息失败:", e);
    if (changeContainer) changeContainer.innerHTML = "加载失败。";
    if (currentContainer) currentContainer.innerHTML = "加载失败。";
  }
}

function renderProcessChanges(changes) {
  var container = document.querySelector("#processChangeList");
  if (!container) return;
  
  if (!changes || changes.length === 0) {
    container.innerHTML = "暂无进程变化。";
    return;
  }
  
  container.innerHTML = changes.slice(0, 50).map(function(event) {
    var label = event.type === "started" ? "启动" : "退出";
    return '<div class="process-change-item ' + event.type + '">' +
      '<div><strong>' + label + '</strong> ' + event.name + ' (PID: ' + event.pid + ')</div>' +
      '<div>' + event.time + '</div>' +
      '<div>父进程: ' + (event.ppid || "-") + ' ' + (event.pname || "") + '</div>' +
      '<div>CPU: ' + event.cpu + '% 内存: ' + event.mem + 'MB</div>' +
      '<div>命令行: ' + formatCommandLine(event.cmdline) + '</div>' +
      '</div>';
  }).join("");
}

function renderCurrentProcesses(processes) {
  var container = document.querySelector("#currentProcesses");
  if (!container) return;
  
  if (!processes || processes.length === 0) {
    container.innerHTML = "当前未检索到进程信息。";
    return;
  }
  
  var sortedProcesses = processes.slice().sort(function(a, b) {
    return (b.cpu || 0) - (a.cpu || 0);
  });
  
  container.innerHTML = '<table class="process-table">' +
    '<thead><tr><th>进程名</th><th>PID</th><th>CPU%</th><th>内存(MB)</th><th>路径</th></tr></thead>' +
    '<tbody>' + sortedProcesses.slice(0, 30).map(function(p) {
      return '<tr>' +
        '<td>' + (p.name || "-") + '</td>' +
        '<td>' + (p.pid || "-") + '</td>' +
        '<td>' + (p.cpu || "0") + '</td>' +
        '<td>' + (p.mem || "0") + '</td>' +
        '<td title="' + (p.path || '') + '">' + formatCommandLine(p.path || p.cmdline || '') + '</td>' +
        '</tr>';
    }).join("") + '</tbody></table>';
}

async function startMonitoring() {
  var btn = document.querySelector("#startButton");
  if (btn) btn.disabled = true;
  
  try {
    var response = await fetchApi("/monitor/start", { method: "POST" });
    if (response && response.success) {
      await loadMonitorStatus();
      setTimeout(loadMonitorProcesses, 1000);
    } else {
      alert(response && response.message || "启动监控失败。");
    }
  } catch (e) {
    console.error("启动监控失败:", e);
    alert("启动监控失败，请稍后重试。");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function pauseMonitoring() {
  var btn = document.querySelector("#pauseButton");
  if (btn) btn.disabled = true;
  
  try {
    var response = await fetchApi("/monitor/pause", { method: "POST" });
    if (response && response.success) {
      await loadMonitorStatus();
    } else {
      alert(response && response.message || "暂停监控失败。");
    }
  } catch (e) {
    console.error("暂停监控失败:", e);
    alert("暂停监控失败，请稍后重试。");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function stopMonitoring() {
  var btn = document.querySelector("#stopButton");
  if (btn) btn.disabled = true;
  
  try {
    var response = await fetchApi("/monitor/stop", { method: "POST" });
    if (response && response.success) {
      localStorage.setItem("winmonitor_menu_message", "监控已退出，已生成新日志，请及时查看。返回菜单查看最新记录。");
      window.location.href = "/menu";
      return;
    }
    alert(response && response.message || "退出监控失败。");
  } catch (e) {
    console.error("停止监控失败:", e);
    alert("停止监控失败，请稍后重试。");
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ==================== 实时告警功能 ====================
var alertEventSource = null;
var currentAlerts = [];

function playAlertSound() {
  try {
    var audioContext = new (window.AudioContext || window.webkitAudioContext)();
    var oscillator = audioContext.createOscillator();
    var gainNode = audioContext.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);
    
    oscillator.frequency.value = 880;
    oscillator.type = "sine";
    gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
    
    oscillator.start(audioContext.currentTime);
    oscillator.stop(audioContext.currentTime + 0.5);
  } catch (e) {
    console.log("无法播放警报声音:", e);
  }
}

function showRealtimeAlert(alert) {
  playAlertSound();
  
  if ("Notification" in window && Notification.permission === "granted") {
    new Notification("严重告警", {
      body: alert.title + ": " + alert.message,
      tag: "critical-alert"
    });
  }
}

function addAlertToPanel(alert) {
  currentAlerts.unshift(alert);
  if (currentAlerts.length > 20) {
    currentAlerts = currentAlerts.slice(0, 20);
  }
  updateCriticalAlertPanel();
}

function updateCriticalAlertPanel() {
  var panel = document.querySelector("#criticalAlertPanel");
  if (!panel) return;
  
  if (currentAlerts.length === 0) {
    panel.innerHTML = "<p>暂无严重告警。</p>";
    return;
  }
  
  panel.innerHTML = currentAlerts.map(function(alert) {
    var categoryCn = alert.category_cn || alert.category || "监控事件";
    return '<div class="critical-alert-item">' +
      '<div class="critical-alert-header">' +
      '<span class="critical-alert-category">' + categoryCn + '</span>' +
      '<span class="critical-alert-time">' + alert.timestamp + '</span>' +
      '</div>' +
      '<div class="critical-alert-content">' +
      '<strong>' + alert.title + '</strong>' +
      '<p>' + alert.message + '</p>' +
      '</div></div>';
  }).join("");
}

function startCriticalAlertStream() {
  var token = getAuthToken();
  if (!token) return;
  
  if (alertEventSource) {
    alertEventSource.close();
  }
  
  try {
    var url = apiBase + "/monitor/stream-alerts?token=" + encodeURIComponent(token);
    alertEventSource = new EventSource(url);
    
    alertEventSource.onopen = function() {
      console.log("实时告警连接已建立");
    };
    
    alertEventSource.onmessage = function(event) {
      try {
        var data = JSON.parse(event.data);
        if (data.type === "alert") {
          addAlertToPanel(data.alert);
          showRealtimeAlert(data.alert);
        }
      } catch (e) {
        console.log("解析告警数据失败:", e);
      }
    };
    
    alertEventSource.onerror = function() {
      console.log("实时告警连接错误，尝试重连...");
      setTimeout(function() {
        if (alertEventSource && alertEventSource.readyState === EventSource.CLOSED) {
          startCriticalAlertStream();
        }
      }, 5000);
    };
  } catch (e) {
    console.error("无法建立实时告警连接:", e);
  }
}

function stopCriticalAlertStream() {
  if (alertEventSource) {
    alertEventSource.close();
    alertEventSource = null;
  }
  currentAlerts = [];
}

async function loadInitialCriticalAlerts() {
  try {
    var result = await fetchApi("/monitor/critical-alerts");
    if (result && result.success) {
      currentAlerts = result.critical_alerts || [];
      updateCriticalAlertPanel();
    }
  } catch (e) {
    console.error("加载初始告警失败:", e);
  }
}

function initPage() {
  var userName = getUserName();
  var isAdmin = getAdminFlag();
  
  var userNameEl = document.querySelector("#userName");
  var userRoleEl = document.querySelector("#userRole");
  if (userNameEl) userNameEl.textContent = userName;
  if (userRoleEl) userRoleEl.textContent = isAdmin ? "管理员" : "普通用户";

  var adminLink = document.querySelector("#adminLink");
  if (adminLink) {
    adminLink.style.display = isAdmin ? "inline-flex" : "none";
  }

  var logoutBtn = document.querySelector("#logoutButton");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", function() {
      stopCriticalAlertStream();
      logout();
    });
  }

  var refreshBtn = document.querySelector("#refreshButton");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", loadMonitorStatus);
  }

  var viewLogsBtn = document.querySelector("#viewLogsButton");
  if (viewLogsBtn) {
    viewLogsBtn.addEventListener("click", function() {
      window.location.href = "/logs.html";
    });
  }

  var viewProcessesBtn = document.querySelector("#viewProcessesButton");
  if (viewProcessesBtn) {
    viewProcessesBtn.addEventListener("click", loadMonitorProcesses);
  }

  var startBtn = document.querySelector("#startButton");
  if (startBtn) {
    startBtn.addEventListener("click", startMonitoring);
  }

  var pauseBtn = document.querySelector("#pauseButton");
  if (pauseBtn) {
    pauseBtn.addEventListener("click", pauseMonitoring);
  }

  var stopBtn = document.querySelector("#stopButton");
  if (stopBtn) {
    stopBtn.addEventListener("click", stopMonitoring);
  }

  loadMonitorStatus();
  loadMonitorProcesses();
  
  loadInitialCriticalAlerts();
  startCriticalAlertStream();
}

document.addEventListener("DOMContentLoaded", function() {
  if (!getAuthToken()) {
    window.location.href = "/login";
    return;
  }
  initPage();
});
