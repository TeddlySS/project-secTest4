// leaderboard.js
import { supabase } from "./supabaseClient.js";
// ----------------------------------------------------
// ADD THIS IMPORT: Assumes setupNavUser is in navAuth.js
import { setupNavUser } from "./navAuth.js";
// ----------------------------------------------------

const podiumContainer = document.getElementById("podiumContainer");
const leaderboardList = document.getElementById("leaderboardList");

const REFRESH_INTERVAL_MS = 30_000; // 30s

const hamburgerBtn = document.getElementById("hamburgerBtn");
const navContainer = document.querySelector(".nav-container");

if (hamburgerBtn && navContainer) {
  hamburgerBtn.addEventListener("click", () => {
    // บรรทัดนี้จะเพิ่ม/ลบ คลาส 'menu-active' ให้กับ nav-container
    navContainer.classList.toggle("menu-active");
  });
}

// ==========================================
// Auth UI Hiding (handleInitialAuthUI)
// ==========================================

// FIX: This function handles the flicker/visibility of the Sign In vs Profile pill
async function handleInitialAuthUI() {
  // Check session status immediately
  const {
    data: { session },
  } = await supabase.auth.getSession();
  const user = session?.user;

  const signInBtn = document.getElementById("navSignInBtn");
  const profileBtn = document.getElementById("navProfileBtn");

  if (user) {
    // Reveal profile link
    if (profileBtn) profileBtn.classList.remove("loading-hidden");
    if (signInBtn) signInBtn.style.display = "none";
  } else {
    // Reveal sign-in button
    if (signInBtn) signInBtn.classList.remove("loading-hidden");
    if (profileBtn) profileBtn.style.display = "none";
  }
}

// UTIL: format numbers (commas)
function fmt(n) {
  return n?.toLocaleString?.() ?? n;
}

// Renders a single podium card
function createPodiumCard(rankObj, place) {
  // place: 1 | 2 | 3
  const div = document.createElement("div");
  div.className = `podium-item ${
    place === 1 ? "first-place" : place === 2 ? "second-place" : "third-place"
  }`;

  const avatarInitials = (rankObj.display_name || rankObj.username || "U")
    .slice(0, 2)
    .toUpperCase();

  div.innerHTML = `
    <div class="podium-avatar">
      <div class="avatar-circle">${avatarInitials}</div>
      <div class="crown ${
        place === 1 ? "gold" : place === 2 ? "silver" : "bronze"
      }">
        ${place === 1 ? "👑" : place === 2 ? "🥈" : "🥉"}
      </div>
    </div>
    <div class="podium-info">
      <h3>${escapeHtml(rankObj.display_name || rankObj.username)}</h3>
      <p class="level">${rankObj.challenges_solved ?? 0} Solved</p>
      <p class="xp">${fmt(rankObj.score)} Points</p>
    </div>
    <div class="podium-base ${
      place === 1 ? "first" : place === 2 ? "second" : "third"
    }">
      <div class="rank-number">${place}</div>
    </div>
  `;
  return div;
}

// Very small HTML-escape helper
function escapeHtml(s) {
  if (!s) return "";
  return s.replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[c])
  );
}

// Render top-3 podium
function renderPodium(rows) {
  podiumContainer.innerHTML = ""; // clear
  const top3 = rows.slice(0, 3);

  if (top3.length === 0) {
    podiumContainer.innerHTML = `<div class="empty-podium">No solvers yet</div>`;
    return;
  }

  // keep stable layout: second, first, third (if available)
  const second = top3[1] ?? null;
  const first = top3[0] ?? null;
  const third = top3[2] ?? null;

  if (second) podiumContainer.appendChild(createPodiumCard(second, 2));
  if (first) podiumContainer.appendChild(createPodiumCard(first, 1));
  if (third) podiumContainer.appendChild(createPodiumCard(third, 3));
}

// Render full leaderboard list
function renderLeaderboard(rows, currentUserId = null) {
  leaderboardList.innerHTML = ""; // clear

  // The static HTML header row already exists in leaderboard.html

  rows.forEach((row) => {
    const r = document.createElement("div");
    r.className = "leaderboard-item leaderboard-row";

    // Check for top 3 rank and add color class
    if (row.rank === 1) {
      r.classList.add("rank-gold-row");
    } else if (row.rank === 2) {
      r.classList.add("rank-silver-row");
    } else if (row.rank === 3) {
      r.classList.add("rank-bronze-row");
    }

    if (currentUserId && +currentUserId === +row.user_id) {
      r.classList.add("current-user-row");
    }
    r.innerHTML = `
      <div class="col rank">${row.rank}</div>
      <div class="col user">
        <div class="user-meta">
          <div class="user-info">
            <div class="username">${escapeHtml(
              row.display_name || row.username
            )}</div>
            </div>
        </div>
      </div>
      <div class="col solved">${row.challenges_solved ?? 0}</div>
      <div class="col points">${fmt(row.score)}</div>
    `;
    leaderboardList.appendChild(r);
  });

  if (rows.length === 0) {
    const note = document.createElement("div");
    note.className = "empty-note";
    note.textContent = "No players to show yet.";
    leaderboardList.appendChild(note);
  }
}

// Attempt to get currently logged in user (supabase auth)
async function getCurrentUser() {
  try {
    const { data, error } = await supabase.auth.getUser();
    if (error) {
      return null;
    }
    return data?.user ?? null;
  } catch (e) {
    return null;
  }
}

// Fetch leaderboard via RPC get_leaderboard(limit_count)
async function fetchLeaderboard(limitCount = 50) {
  try {
    // Prefer RPC function (get_leaderboard) you defined server-side
    const { data, error } = await supabase.rpc("get_leaderboard", {
      limit_count: limitCount,
    });

    if (error) {
      console.error("RPC get_leaderboard error:", error);
      // Fallback: query users directly (public select allowed by your policy)
      const { data: usersData, error: usersError } = await supabase
        .from("users")
        .select(`user_id, username, display_name, avatar, score`)
        .order("score", { ascending: false })
        .limit(limitCount);

      if (usersError) {
        throw usersError;
      }

      // Convert into rows with minimal shape
      const fallbackRows = (usersData || []).map((u, idx) => ({
        rank: idx + 1,
        user_id: u.user_id,
        username: u.username,
        display_name: u.display_name,
        avatar: u.avatar,
        score: u.score ?? 0,
        challenges_solved: 0,
      }));

      return fallbackRows;
    }

    // RPC returned rows already in desired shape:
    // rank, user_id, username, display_name, avatar, score, challenges_solved
    return data ?? [];
  } catch (err) {
    console.error("fetchLeaderboard error", err);
    return [];
  }
}

// Try to get numeric rank for current user by calling get_user_rank(user_id_param)
async function fetchCurrentUserRank(appUser) {
  if (!appUser) return null;

  // Two possibilities: your auth UID maps to users.user_id or not.
  // The schema uses integer user_id, while Supabase auth gives a UUID.
  // Try to find a matching users row first by email / metadata if available.
  try {
    // 1) If auth user has an email, try to find users row by email
    const email =
      appUser.email ?? (appUser.user_metadata && appUser.user_metadata.email);
    if (email) {
      const { data: u, error: err } = await supabase
        .from("users")
        .select("user_id")
        .eq("email", email)
        .limit(1)
        .single();
      if (!err && u && u.user_id) {
        // call RPC get_user_rank if available
        try {
          const { data: rankData, error: rpcErr } = await supabase.rpc(
            "get_user_rank",
            { user_id_param: u.user_id }
          );
          if (!rpcErr) return rankData;
        } catch (e) {
          // ignore and fallback
        }
        // fallback: compute rank by counting users with higher score
        const { count, error: cErr } = await supabase
          .from("users")
          .select("user_id", { count: "exact", head: true })
          .gt(
            "score",
            (
              await supabase
                .from("users")
                .select("score")
                .eq("user_id", u.user_id)
                .limit(1)
                .single()
            ).data.score
          );
        if (!cErr) {
          return (count ?? 0) + 1;
        }
      }
    }

    // 2) As a fallback (no email match), try to find by username from user_metadata
    const username = appUser.user_metadata?.username;
    if (username) {
      const { data: u2, error: err2 } = await supabase
        .from("users")
        .select("user_id")
        .eq("username", username)
        .limit(1)
        .single();
      if (!err2 && u2?.user_id) {
        const { data: rankData, error: rpcErr } = await supabase.rpc(
          "get_user_rank",
          { user_id_param: u2.user_id }
        );
        if (!rpcErr) return rankData;
      }
    }
  } catch (e) {
    console.warn("fetchCurrentUserRank fallback failed", e);
  }

  return null;
}

// Main refresh flow
let lastFetch = 0;
async function refreshLeaderboard() {
  const now = Date.now();
  if (now - lastFetch < 1000) return;
  lastFetch = now;

  // show loading skeleton (optional)
  leaderboardList.innerHTML = `<div class="loading">Loading leaderboard...</div>`;

  const [appUser] = await Promise.all([getCurrentUser()]);

  const rows = await fetchLeaderboard(200); // get top 200 by default

  // Render podium and list
  renderPodium(rows);
  // try to get numeric user id for highlighting current user
  let currentUserId = null;
  if (appUser) {
    // attempt to resolve user.user_id (int) from our users table by email
    try {
      const email =
        appUser.email ?? (appUser.user_metadata && appUser.user_metadata.email);
      if (email) {
        const { data: u, error: e } = await supabase
          .from("users")
          .select("user_id")
          .eq("email", email)
          .limit(1)
          .maybeSingle();
        if (!e && u && u.user_id) currentUserId = u.user_id;
      } else if (appUser.user_metadata?.username) {
        const { data: u2, error: e2 } = await supabase
          .from("users")
          .select("user_id")
          .eq("username", appUser.user_metadata.username)
          .limit(1)
          .maybeSingle();
        if (!e2 && u2 && u2.user_id) currentUserId = u2.user_id;
      }
    } catch (e) {
      console.warn("resolve current user id failed", e);
    }
  }

  renderLeaderboard(rows, currentUserId);

  // show current rank in widget (if present)
  const currentRankWidget = document.querySelector(
    ".current-rank-widget .rank-widget-number"
  );
  if (currentRankWidget) {
    let rankToShow = null;
    if (appUser && currentUserId) {
      // try RPC get_user_rank
      try {
        const { data: rankData, error: rpcErr } = await supabase.rpc(
          "get_user_rank",
          { user_id_param: currentUserId }
        );
        if (!rpcErr) rankToShow = rankData;
      } catch (e) {
        // fallback: find in rows
        const found = rows.find((r) => +r.user_id === +currentUserId);
        rankToShow = found ? found.rank : null;
      }
    }
    currentRankWidget.textContent = rankToShow ?? "-";
  }
}

// initial load
refreshLeaderboard();

// auto-refresh interval
setInterval(refreshLeaderboard, REFRESH_INTERVAL_MS);

document.addEventListener("DOMContentLoaded", async () => {
  // 1. Run the auth check and UI update immediately (fixes flicker)
  await handleInitialAuthUI();

  // 2. NOW CALL setupNavUser: This fetches the user's username and avatar and updates the DOM
  await setupNavUser(); // <<< REQUIRED FIX FOR USERNAME LOAD

  // Optional: allow manual refresh via clicking header or a button you may add
  document.addEventListener("click", (ev) => {
    if (ev.target && ev.target.matches && ev.target.matches(".page-title")) {
      refreshLeaderboard();
    }
  });
});
