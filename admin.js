import { supabase } from "./supabaseClient.js";

// ==========================================
// Global State
// ==========================================
const state = {
  currentSection: "dashboard",
  challenges: [],
  users: [],
  submissions: [],
  hints: [],
  selectedChallenge: null,
  currentUser: null,
};

const hamburgerBtn = document.getElementById("hamburgerBtn");
const sidebar = document.getElementById("sidebar");

// ==========================================
// Admin Access Check
// ==========================================
async function checkAdminAccess() {
  try {
    const { data: authData, error: authError } = await supabase.auth.getUser();

    if (authError || !authData.user) {
      return { success: false, reason: "NOT_AUTHENTICATED" };
    }

    const authUser = authData.user;

    const { data: userData, error: userError } = await supabase
      .from("users")
      .select(
        "user_id, username, email, display_name, role, score, avatar, status"
      )
      .eq("email", authUser.email)
      .single();

    if (userError || !userData) {
      console.error("Database error or User not found:", userError);
      return { success: false, reason: "USER_NOT_FOUND" };
    }

    if (userData.role !== "admin") {
      return { success: false, reason: "NOT_ADMIN" };
    }

    if (userData.status !== "active") {
      return { success: false, reason: "INACTIVE" };
    }

    state.currentUser = userData;
    const adminUsernameEl = document.getElementById("adminUsername");
    if (adminUsernameEl) {
      adminUsernameEl.textContent = `${
        userData.display_name || userData.username
      } (Admin)`;
    }

    return { success: true };
  } catch (err) {
    console.error("Unexpected error in checkAdminAccess:", err);
    return { success: false, reason: "UNEXPECTED_ERROR" };
  }
}

// ==========================================
// Page Initialization & Navigation
// ==========================================
document.addEventListener("DOMContentLoaded", async () => {
  const mainContent =
    document.querySelector(".admin-container") || document.body;
  mainContent.style.display = "none";

  const loadingSpinner = document.getElementById("loadingSpinner");
  if (loadingSpinner) {
    loadingSpinner.style.display = "flex";
  }

  const accessResult = await checkAdminAccess();

  if (accessResult.success) {
    if (loadingSpinner) {
      loadingSpinner.style.display = "none";
    }

    mainContent.style.display = "block";

    initializeAdmin();
    setupEventListeners();
    loadDashboardData();
  } else {
    let alertMessage = "❌ คุณไม่มีสิทธิ์เข้าถึงหน้านี้";
    switch (accessResult.reason) {
      case "NOT_AUTHENTICATED":
      case "USER_NOT_FOUND":
        alertMessage = "กรุณาเข้าสู่ระบบก่อน";
        break;
      case "NOT_ADMIN":
        alertMessage = "❌ คุณไม่มีสิทธิ์เข้าถึงหน้านี้ (Admin เท่านั้น)";
        break;
      case "INACTIVE":
        alertMessage = "❌ บัญชีของคุณถูกระงับ";
        break;
    }

    alert(alertMessage);
    window.location.href = "/login.html";
  }
});

function initializeAdmin() {
  showSection("dashboard");
}

function showSection(sectionName) {
  state.currentSection = sectionName;

  document
    .querySelectorAll(".menu-item")
    .forEach((item) => item.classList.remove("active"));
  document
    .querySelector(`[onclick="showSection('${sectionName}')"]`)
    ?.classList.add("active");

  document
    .querySelectorAll(".admin-section")
    .forEach((sec) => sec.classList.remove("active"));
  document.getElementById(`section-${sectionName}`)?.classList.add("active");

  loadSectionData(sectionName);
}

function loadSectionData(sectionName) {
  switch (sectionName) {
    case "dashboard":
      loadDashboardData();
      break;
    case "challenges":
      loadChallenges();
      break;
    case "hints":
      loadHintsChallenges();
      break;
    case "users":
      loadUsers();
      break;
    case "submissions":
      loadSubmissions();
      break;
    // statistics and files omitted
  }
}

function switchToUserView() {
  try {
    sessionStorage.removeItem("viewUserId");
    sessionStorage.removeItem("adminPanel");
    setTimeout(() => {
      window.location.href = "home.html";
    }, 100);
  } catch (error) {
    showAlert("❌ Error switching to user view", "error");
  }
}

function setupEventListeners() {
  document
    .getElementById("categoryFilter")
    ?.addEventListener("change", filterChallenges);
  document
    .getElementById("difficultyFilter")
    ?.addEventListener("change", filterChallenges);

  // Hamburger menu toggle logic
  const hamburgerBtn = document.getElementById("hamburgerBtn");
  const sidebar = document.getElementById("sidebar");

  if (hamburgerBtn && sidebar) {
    hamburgerBtn.addEventListener("click", () => {
      sidebar.classList.toggle("open"); // This toggles the 'open' class
    });

    document.querySelectorAll(".sidebar-menu .menu-item").forEach((link) => {
      link.addEventListener("click", () => {
        sidebar.classList.remove("open");
      });
    });
  }
}

// ==========================================
// Dashboard Helpers (Data Loading)
// ==========================================

// Helper function to get count for a specific date range
const getCount = async (table, dateField, start, end, filters = {}) => {
  let query = supabase.from(table).select("*", { count: "exact", head: true });

  if (dateField && start) {
    query = query.gte(dateField, start);
  }
  if (dateField && end) {
    query = query.lt(dateField, end);
  }

  Object.keys(filters).forEach((key) => {
    query = query.eq(key, filters[key]);
  });

  const { count, error } = await query;
  if (error) {
    console.warn(`Error counting ${table}:`, error);
    return 0;
  }
  return count || 0;
};

// Helper function to get distinct user IDs for a date range
const getDistinctActiveUsers = async (table, dateField, start, end) => {
  let query = supabase
    .from(table)
    .select("user_id", { count: "exact", head: false });

  if (dateField && start) {
    query = query.gte(dateField, start);
  }
  if (dateField && end) {
    query = query.lt(dateField, end);
  }

  const { data, error } = await query;
  if (error) {
    console.warn(`Error counting distinct users in ${table}:`, error);
    return [];
  }
  return Array.from(new Set((data || []).map((item) => item.user_id)));
};

// --- Activity Table Renderer ---
function renderActivityStatsTable(metrics) {
  const tbody = document.getElementById("activityStatsBody");
  if (!tbody || !metrics) {
    console.warn("Activity stats tbody not found or no metrics data");
    return;
  }

  let html = "";

  for (const [metricName, stats] of Object.entries(metrics)) {
    const { today, thisWeek, total } = stats;

    const todayDisplay = today?.toLocaleString?.() || "0";
    const thisWeekDisplay = thisWeek?.toLocaleString?.() || "0";
    const totalDisplay = total?.toLocaleString?.() || "0";

    html += `
            <tr>
                <td><strong>${metricName}</strong></td>
                <td class="stat-number">${todayDisplay}</td>
                <td class="stat-number">${thisWeekDisplay}</td>
                <td class="stat-number">${totalDisplay}</td>
            </tr>
        `;
  }

  tbody.innerHTML = html;
}

// ==========================================
// Dashboard (Main Loader) - RESTORED LOGIC
// ==========================================
async function loadDashboardData() {
  try {
    console.log("📊 Loading dashboard data...");

    const now = new Date();
    const todayStart = new Date(now.setHours(0, 0, 0, 0)).toISOString();
    const weekStart = new Date(
      new Date().setDate(now.getDate() - 7)
    ).toISOString();

    const promises = [
      supabase
        .from("challenges")
        .select("*", { count: "exact", head: true })
        .eq("is_active", true),
      supabase
        .from("users")
        .select("*", { count: "exact", head: true })
        .eq("status", "active"),
      supabase.from("submissions").select("*", { count: "exact", head: true }),
      getCount("submissions", null, null, null, { is_correct: true }),

      getCount("users", "created_at", todayStart, null),
      getCount("users", "created_at", weekStart, null),
      getCount("users", null, null, null),

      getCount("user_progress", "solved_at", todayStart, null, {
        is_solved: true,
      }),
      getCount("user_progress", "solved_at", weekStart, null, {
        is_solved: true,
      }),
      getCount("user_progress", null, null, null, { is_solved: true }),

      getCount("submissions", "submitted_at", todayStart, null),
      getCount("submissions", "submitted_at", weekStart, null),
      getCount("submissions", null, null, null),

      getDistinctActiveUsers("submissions", "submitted_at", todayStart, null),
      getDistinctActiveUsers("user_hints", "used_at", todayStart, null),

      getDistinctActiveUsers("submissions", "submitted_at", weekStart, null),
      getDistinctActiveUsers("user_hints", "used_at", weekStart, null),

      getDistinctActiveUsers("submissions", "submitted_at", null, null),
      getDistinctActiveUsers("user_hints", "used_at", null, null),

      getCount("user_hints", "used_at", todayStart, null),
      getCount("user_hints", "used_at", weekStart, null),
      getCount("user_hints", null, null, null),
    ];

    const results = await Promise.all(promises);

    let i = 0;
    const challengeResult = results[i++],
      userResult = results[i++],
      submissionResult = results[i++],
      correctCount = results[i++];
    const usersToday = results[i++],
      usersThisWeek = results[i++],
      usersTotal = results[i++];
    const solvesToday = results[i++],
      solvesThisWeek = results[i++],
      solvesTotal = results[i++];
    const submissionsToday = results[i++],
      submissionsThisWeek = results[i++],
      submissionsTotal = results[i++];
    const activeTodaySubmissions = results[i++],
      activeTodayHints = results[i++];
    const activeWeekSubmissions = results[i++],
      activeWeekHints = results[i++];
    const allActiveSubmissions = results[i++],
      allActiveHints = results[i++];
    const hintsToday = results[i++],
      hintsThisWeek = results[i++],
      hintsTotal = results[i++];

    const challengeCount = challengeResult.count || 0;
    const userCount = userResult.count || 0;
    const submissionCount = submissionResult.count || 0;

    const activeUsersToday = Array.from(
      new Set([...activeTodaySubmissions, ...activeTodayHints])
    ).length;
    const activeUsersThisWeek = Array.from(
      new Set([...activeWeekSubmissions, ...activeWeekHints])
    ).length;
    const activeUsersTotal = Array.from(
      new Set([...allActiveSubmissions, ...allActiveHints])
    ).length;

    const solveRate =
      submissionCount && submissionCount > 0
        ? (((correctCount || 0) / submissionCount) * 100).toFixed(1)
        : 0;

    const totalChallengesEl = document.getElementById("totalChallenges");
    const totalUsersEl = document.getElementById("totalUsers");
    const totalSubmissionsEl = document.getElementById("totalSubmissions");
    const solveRateEl = document.getElementById("solveRate");

    if (totalChallengesEl) totalChallengesEl.textContent = challengeCount;
    if (totalUsersEl) totalUsersEl.textContent = userCount;
    if (totalSubmissionsEl) totalSubmissionsEl.textContent = submissionCount;
    if (solveRateEl) solveRateEl.textContent = solveRate + "%";

    const activityData = {
      "New Registrations": {
        today: usersToday,
        thisWeek: usersThisWeek,
        total: usersTotal,
      },
      "Challenge Solves": {
        today: solvesToday,
        thisWeek: solvesThisWeek,
        total: solvesTotal,
      },
      Submissions: {
        today: submissionsToday,
        thisWeek: submissionsThisWeek,
        total: submissionsTotal,
      },
      // "Active Users": {
      //   today: activeUsersToday,
      //   thisWeek: activeUsersThisWeek,
      //   total: activeUsersTotal,
      // },
      "Hints Used": {
        today: hintsToday,
        thisWeek: hintsThisWeek,
        total: hintsTotal,
      },
    };

    renderActivityStatsTable(activityData);

    console.log("✅ Dashboard data loaded:", {
      challenges: challengeCount,
      users: userCount,
      submissions: submissionCount,
      solveRate: solveRate + "%",
    });

    initializeCharts();
  } catch (error) {
    console.error("Error loading dashboard:", error);
    showAlert("❌ ไม่สามารถโหลดข้อมูลแดชบอร์ด", "error");
  }
}

function initializeCharts() {
  console.log("📈 Charts initialized");
}

// ==========================================
// Challenges
// ==========================================
async function loadChallenges() {
  try {
    const { data: challenges, error } = await supabase
      .from("challenges")
      .select(
        "challenge_id, code, title, category, difficulty, score_base, is_active, visibility"
      )
      .order("created_at", { ascending: false });

    if (error) {
      showAlert("❌ ไม่สามารถโหลดข้อมูลแบบกึกหัด", "error");
      return;
    }

    state.challenges = challenges || [];
    renderChallengesTable();
  } catch (error) {
    showAlert("❌ เกิดข้อผิดพลาดในการโหลดแบบกึกหัด", "error");
  }
}

function renderChallengesTable(challenges = state.challenges) {
  const tbody = document.getElementById("challengesTableBody");
  if (!tbody) return;

  const challengesToRender = challenges;
  if (challengesToRender.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="5" style="text-align:center; padding: 20px;">ไม่มีแบบกึกหัด</td></tr>';
    return;
  }

  tbody.innerHTML = challengesToRender
    .map(
      (ch) => `
    <tr>
      <td><strong>${ch.code || "-"}</strong></td>
      <td>${ch.title}</td>
      <td><span class="badge badge-${ch.category?.toLowerCase()}">${
        ch.category || "-"
      }</span></td>
      <td><span class="badge badge-${ch.difficulty?.toLowerCase()}">${
        ch.difficulty || "-"
      }</span></td>
      <td>${ch.score_base || 0}</td>
      </tr>
  `
    )
    .join("");
}

function filterChallenges() {
  const searchTerm =
    document.getElementById("challengeSearch")?.value.toLowerCase() || "";
  const categoryFilter = document.getElementById("categoryFilter")?.value || "";
  const difficultyFilter =
    document.getElementById("difficultyFilter")?.value || "";

  const filteredChallenges = state.challenges.filter((ch) => {
    const matchesSearch =
      ch.code.toLowerCase().includes(searchTerm) ||
      ch.title.toLowerCase().includes(searchTerm);

    const matchesCategory = !categoryFilter || ch.category === categoryFilter;
    const matchesDifficulty =
      !difficultyFilter || ch.difficulty === difficultyFilter;

    return matchesSearch && matchesCategory && matchesDifficulty;
  });

  renderChallengesTable(filteredChallenges);
}

// ==========================================
// Hints (Restored Placeholder)
// ==========================================
async function loadHintsChallenges() {
  try {
    console.log("💡 Loading hints...");
    // Minimal data setting to prevent crashes
    // If you need actual implementation, you'll need the render function here.
  } catch (error) {
    console.error("Error loading hints:", error);
    showAlert("❌ เกิดข้อผิดพลาดในการโหลด Hints", "error");
  }
}

// ==========================================
// Users (FIXED: Role Management & Deletion)
// ==========================================
async function loadUsers() {
  try {
    const { data: users, error } = await supabase
      .from("users")
      .select(
        "user_id, username, email, display_name, role, score, status, created_at"
      )
      .order("created_at", { ascending: false });

    if (error) {
      showAlert("❌ ไม่สามารถโหลดข้อมูลผู้ใช้", "error");
      return;
    }

    state.users = users || [];
    filterUsers();
  } catch (error) {
    showAlert("❌ เกิดข้อผิดพลาดในการโหลดผู้ใช้", "error");
  }
}

function renderUsersTable(usersToRender = state.users) {
  const tbody = document.getElementById("usersTableBody");
  if (!tbody) return;

  if (usersToRender.length === 0) {
    // Colspan is 8
    tbody.innerHTML =
      '<tr><td colspan="7" style="text-align:center; padding: 20px;">ไม่มีผู้ใช้</td></tr>';
    return;
  }

  // Define the current admin's username for comparison
  const currentAdminUsername = state.currentUser
    ? state.currentUser.username
    : null;

  tbody.innerHTML = usersToRender
    .map(
      (u, index) => `
    <tr>
      <td><strong>${u.username}</strong></td>
      <td>${u.email}</td>
      <td>${u.display_name || "-"}</td>
      <td><span class="badge badge-${
        u.role === "admin"
          ? "danger"
          : u.role === "moderator"
          ? "warning"
          : "info"
      }">${u.role}</span></td>
      <td><strong>${u.score || 0}</strong></td>
      <td>${new Date(u.created_at).toLocaleDateString()}</td>
      <td><span class="badge badge-${
        u.status === "active" ? "success" : "danger"
      }
      
      <td style="white-space: nowrap; display: flex; justify-content: center; gap: 0.5rem;">
        ${
          // If the user is NOT the current admin, show the action buttons
          u.username !== currentAdminUsername
            ? `
              <button class="action-btn edit" onclick="changeUserRole('${u.user_id}')">Change Role</button>
              
              <button class="action-btn delete" onclick="deleteUser('${u.user_id}')">Delete User</button>
            `
            : `<span class="badge badge-info">‎ ‎ </span>` // Indicate the current admin user
        }
      </td>
    </tr>
  `
    )
    .join("");
}

function filterUsers() {
  const roleFilterElement = document.getElementById("roleFilter");
  const roleFilterValue = roleFilterElement ? roleFilterElement.value : "All";

  const filteredUsers = state.users.filter((u) => {
    if (roleFilterValue !== "All" && u.role !== roleFilterValue) {
      return false;
    }
    return true;
  });

  renderUsersTable(filteredUsers);
}

// --- Function to initiate role change to ADMIN role (FIXED) ---
function changeUserRole(userId) {
  const userIdInt = parseInt(userId);
  const user = state.users.find((u) => u.user_id === userIdInt);

  if (!user) {
    showAlert("❌ ไม่พบผู้ใช้ (User ID mismatch/missing from list)", "error");
    return;
  }

  const currentRole = user.role;
  // MODIFIED LOGIC: Determine the new role based on the current role.
  const newRole = currentRole === "admin" ? "player" : "admin";

  if (
    !confirm(
      `⚠️ ยืนยันเปลี่ยน Role ของ ${user.username} จาก '${currentRole}' เป็น '${newRole}'?`
    )
  ) {
    showAlert("ยกเลิกการเปลี่ยน Role", "info");
    return;
  }

  updateUserRole(userId, newRole);
}

// --- Function to execute the database update (SECURE RPC FIX) ---
async function updateUserRole(userId, newRole) {
  try {
    const { error } = await supabase.rpc("update_user_role_securely", {
      target_user_id: parseInt(userId),
      new_role: newRole,
    });

    if (error) {
      console.error("RPC Update Error:", error);
      throw error;
    }

    loadUsers();

    showAlert(
      `✅ อัปเดต Role สำเร็จ: User ID ${userId} เป็น ${newRole}`,
      "success"
    );
  } catch (error) {
    showAlert(
      "❌ ไม่สามารถอัปเดต Role: Secure RPC failed or internal permission error.",
      "error"
    );
  }
}

async function deleteUser(userId) {
  const userIdInt = parseInt(userId);
  const user = state.users.find((u) => u.user_id === userIdInt);
  const username = user?.username || userId;

  if (
    !confirm(
      `⚠️ ยืนยันการลบผู้ใช้ @${username} (ID: ${userId})?\n\nการดำเนินการนี้จะลบผู้ใช้และข้อมูลทั้งหมดที่เกี่ยวข้อง (Progress, Submissions) อย่างถาวร!`
    )
  ) {
    showAlert("ยกเลิกการลบผู้ใช้", "info");
    return;
  }

  try {
    showAlert(`⏳ กำลังลบผู้ใช้ @${username} อย่างถาวร...`, "warning");

    const { error: rpcError } = await supabase.rpc("secure_delete_user", {
      user_id_to_delete: parseInt(userId),
    });

    if (rpcError) throw rpcError;

    loadUsers();

    showAlert(
      `✅ ลบผู้ใช้ @${username} และข้อมูลที่เกี่ยวข้องทั้งหมดสำเร็จ!`,
      "success"
    );
  } catch (error) {
    showAlert("❌ ไม่สามารถลบผู้ใช้: " + error.message, "error");
  }
}

// ==========================================
// Submissions
// ==========================================
async function loadSubmissions() {
  try {
    const { data: submissions, error: submissionsError } = await supabase
      .from("submissions")
      .select(
        "submission_id, user_id, challenge_id, is_correct, points, submitted_at, flag_submitted, hints_used"
      )
      .order("submitted_at", { ascending: false })
      .limit(100);

    if (submissionsError) {
      showAlert("❌ ไม่สามารถโหลด Submissions", "error");
      return;
    }

    state.submissions = submissions || [];
    const userIds = Array.from(
      new Set(state.submissions.map((s) => s.user_id))
    );
    const challengeIds = Array.from(
      new Set(state.submissions.map((s) => s.challenge_id))
    );

    const [userResults, challengeResults] = await Promise.all([
      supabase.from("users").select("user_id, username").in("user_id", userIds),
      supabase
        .from("challenges")
        .select("challenge_id, title, code")
        .in("challenge_id", challengeIds),
    ]);

    const userMap = (userResults.data || []).reduce((map, user) => {
      map[user.user_id] = user.username;
      return map;
    }, {});

    const challengeMap = (challengeResults.data || []).reduce(
      (map, challenge) => {
        map[challenge.challenge_id] = `${challenge.code || "N/A"} - ${
          challenge.title
        }`;
        return map;
      },
      {}
    );

    const enhancedSubmissions = state.submissions.map((s) => ({
      ...s,
      username: userMap[s.user_id] || s.user_id,
      challengeName: challengeMap[s.challenge_id] || s.challenge_id,
    }));

    state.submissions = enhancedSubmissions;
    renderSubmissionsTable();
  } catch (error) {
    showAlert("❌ เกิดข้อผิดพลาดในการโหลด Submissions", "error");
  }
}

function renderSubmissionsTable() {
  const tbody = document.getElementById("submissionsTableBody");
  if (!tbody) return;

  if (state.submissions.length === 0) {
    // Colspan is 7
    tbody.innerHTML =
      '<tr><td colspan="7" style="text-align:center; padding: 20px;">ไม่มี Submissions</td></tr>';
    return;
  }

  tbody.innerHTML = state.submissions
    .map(
      (s) => `
    <tr>
      <td><strong>${s.username || s.user_id}</strong></td> 
      <td>${s.challengeName || s.challenge_id}</td> 
      <td>${s.flag_submitted || "-"}</td>
      <td><span class="badge badge-${s.is_correct ? "success" : "danger"}">${
        s.is_correct ? "✅" : "❌"
      }</span></td>
      <td><strong>${s.points || 0}</strong></td>
      <td>${s.hints_used || 0}</td> 
      <td>${new Date(s.submitted_at).toLocaleString("th-TH")}</td>
    </tr>
  `
    )
    .join("");
}

function filterSubmissions() {
  const searchTerm =
    document.getElementById("submissionSearch")?.value.toLowerCase() || "";

  const filteredSubmissions = state.submissions.filter((s) => {
    const userMatch = s.username?.toLowerCase().includes(searchTerm);
    const challengeMatch = s.challengeName?.toLowerCase().includes(searchTerm);

    return userMatch || challengeMatch;
  });

  renderSubmissionsTable(filteredSubmissions);
}

// ==========================================
// Utility Functions
// ==========================================

function showAlert(message, type = "info") {
  const alert = document.createElement("div");
  alert.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 15px 20px;
    border-radius: 8px;
    font-weight: bold;
    z-index: 9999;
    animation: slideIn 0.3s ease-out;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    ${type === "success" ? "background: #00ff88; color: #0a0e27;" : ""}
    ${type === "error" ? "background: #ff4444; color: white;" : ""}
    ${type === "info" ? "background: #00ccff; color: #0a0e27;" : ""}
    ${type === "warning" ? "background: #ffaa00; color: #0a0e27;" : ""}
  `;
  alert.textContent = message;
  document.body.appendChild(alert);

  setTimeout(() => {
    alert.style.animation = "slideOut 0.3s ease-out";
    setTimeout(() => alert.remove(), 300);
  }, 3000);
}

async function logoutAdmin() {
  if (!confirm("⚠️ คุณแน่ใจหรือว่าต้องการออกจากระบบ?")) {
    return;
  }

  const { error } = await supabase.auth.signOut();
  if (!error) {
    window.location.href = "/login.html";
  } else {
    showAlert("❌ Error logging out", "error");
  }
}

// ==========================================
// Make functions available globally
// ==========================================
window.logoutAdmin = logoutAdmin;
window.switchToUserView = switchToUserView;
window.showSection = showSection;

window.changeUserRole = changeUserRole;
window.deleteUser = deleteUser;

window.showAlert = showAlert;

window.filterChallenges = filterChallenges;
window.filterUsers = filterUsers;
window.filterSubmissions = filterSubmissions;
