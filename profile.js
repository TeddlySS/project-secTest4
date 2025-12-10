import { supabase } from "./supabaseClient.js";
import { setupNavUser } from "./navAuth.js";
import { logout } from "./login.js";

const hamburgerBtn = document.getElementById("hamburgerBtn");
const navContainer = document.querySelector(".nav-container");

if (hamburgerBtn && navContainer) {
  hamburgerBtn.addEventListener("click", () => {
    // บรรทัดนี้จะเพิ่ม/ลบ คลาส 'menu-active' ให้กับ nav-container เพื่อเปิด/ปิดเมนู
    navContainer.classList.toggle("menu-active");
  });
}

// ✅ Make logout available globally
window.logout = logout;

// State Management
let userData = {};
let editMode = false;

// Initialize Page
document.addEventListener("DOMContentLoaded", async function () {
  createParticles();
  await loadUserData();
  setupNavUser();
});

// ==========================================
// Create Particles
// ==========================================
function createParticles() {
  const particlesContainer = document.getElementById("particles");
  if (!particlesContainer) return;

  for (let i = 0; i < 50; i++) {
    const particle = document.createElement("div");
    particle.className = "particle";
    particle.style.left = Math.random() * 100 + "%";
    particle.style.animationDelay = Math.random() * 15 + "s";
    particle.style.animationDuration = Math.random() * 10 + 10 + "s";
    particlesContainer.appendChild(particle);
  }
}

// ==========================================
// Load User Data from Supabase
// ==========================================
async function loadUserData() {
  try {
    const {
      data: { user: authUser },
      error: sessionError,
    } = await supabase.auth.getUser();

    if (sessionError || !authUser) {
      console.error("No user session:", sessionError);
      window.location.href = "login.html";
      return;
    }

    // Query user data by email since user_id is UUID in auth
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", authUser.email)
      .single();

    if (error) {
      console.error("Error fetching user data:", error);
      window.location.href = "login.html";
      return;
    }

    userData = data;
    console.log("User data loaded:", userData);

    // Populate page with real data
    populatePageData();
  } catch (error) {
    console.error("Load user data error:", error);
    window.location.href = "login.html";
  }
}

// ==========================================
// Populate Page with Real Data
// ==========================================
function populatePageData() {
  // Avatar
  const avatarImg = document.getElementById("avatarPreview");
  if (avatarImg) {
    avatarImg.src =
      userData.avatar ||
      `https://ui-avatars.com/api/?name=${
        userData.username || "User"
      }&size=200&background=00ff88&color=0a0e27&bold=true`;
  }

  // Username in header
  const displayUsername = document.getElementById("displayUsername");
  if (displayUsername) {
    displayUsername.textContent = userData.username;
  }

  // Role
  const userRole = document.getElementById("userRole");
  if (userRole) {
    const roleDisplay =
      (userData.role || "player").charAt(0).toUpperCase() +
      (userData.role || "player").slice(1);
    userRole.textContent = roleDisplay;

    // Add role badge styling
    if (userData.role === "admin") {
      userRole.style.color = "#ff0080";
      userRole.style.fontWeight = "bold";
    } else if (userData.role === "moderator") {
      userRole.style.color = "#ff8c00";
      userRole.style.fontWeight = "bold";
    }
  }

  // ✅ Show admin button if user is admin
  const adminButtonContainer = document.getElementById("adminButtonContainer");
  if (adminButtonContainer) {
    if (userData.role === "admin") {
      adminButtonContainer.style.display = "block";
      console.log("✅ Admin button shown for admin user");
    } else {
      adminButtonContainer.style.display = "none";
    }
  }

  // Form inputs
  const usernameInput = document.getElementById("username");
  if (usernameInput) {
    usernameInput.value = userData.username || "";
    usernameInput.disabled = true; // Username shouldn't be changed
  }

  const displayNameInput = document.getElementById("displayName");
  if (displayNameInput) displayNameInput.value = userData.display_name || "";

  const emailInput = document.getElementById("email");
  if (emailInput) emailInput.value = userData.email || "";

  const memberSinceInput = document.getElementById("memberSince");
  if (memberSinceInput) {
    memberSinceInput.value = userData.created_at
      ? new Date(userData.created_at).toLocaleDateString("en-US", {
          year: "numeric",
          month: "long",
          day: "numeric",
        })
      : "";
    memberSinceInput.disabled = true;
  }

  // Stats
  const userScore = document.getElementById("userScore");
  if (userScore) userScore.textContent = userData.score || 0;

  const userRank = document.getElementById("userRank");
  if (userRank) {
    getUserRank();
  }

  const solvedChallenges = document.getElementById("solvedChallenges");
  if (solvedChallenges) {
    getUserStats();
  }
}

// ==========================================
// Get User Rank from Database
// ==========================================
async function getUserRank() {
  try {
    const { data, error } = await supabase.rpc("get_user_rank", {
      user_id_param: userData.user_id,
    });

    if (!error && data) {
      const rankEl = document.getElementById("userRank");
      if (rankEl) rankEl.textContent = "#" + data;
    } else if (error) {
      console.warn("Error getting rank, setting default:", error);
      const rankEl = document.getElementById("userRank");
      if (rankEl) rankEl.textContent = "#--";
    }
  } catch (err) {
    console.error("Error getting user rank:", err);
    const rankEl = document.getElementById("userRank");
    if (rankEl) rankEl.textContent = "#--";
  }
}

// ==========================================
// Get User Statistics
// ==========================================
async function getUserStats() {
  try {
    const { data, error } = await supabase.rpc("get_user_stats", {
      user_id_param: userData.user_id,
    });

    if (!error && data && data.length > 0) {
      const stats = data[0];
      const solvedEl = document.getElementById("solvedChallenges");
      if (solvedEl) solvedEl.textContent = stats.challenges_solved || 0;
    } else if (error) {
      console.warn("Error getting stats, setting default:", error);
      const solvedEl = document.getElementById("solvedChallenges");
      if (solvedEl) solvedEl.textContent = "0";
    }
  } catch (err) {
    console.error("Error getting user stats:", err);
    const solvedEl = document.getElementById("solvedChallenges");
    if (solvedEl) solvedEl.textContent = "0";
  }
}

// ==========================================
// Avatar Management
// ==========================================
async function handleAvatarChange(event) {
  const file = event.target.files[0];
  if (!file) return;

  // Validation
  if (!file.type.startsWith("image/")) {
    showToast("Please select an image file", "error");
    return;
  }

  if (file.size > 5 * 1024 * 1024) {
    showToast("Image size must be less than 5MB", "error");
    return;
  }

  // Preview
  const reader = new FileReader();
  reader.onload = function (e) {
    const avatarImg = document.getElementById("avatarPreview");
    if (avatarImg) avatarImg.src = e.target.result;
  };
  reader.readAsDataURL(file);

  // Setup File Path (using user_id for folder structure)
  const fileExt = file.name.split(".").pop();
  const filePath = `${userData.user_id}/avatar.${fileExt}`;

  try {
    // Upload to Supabase Storage (using upsert: true to overwrite old file)
    const { error: uploadError } = await supabase.storage
      .from("avatars")
      .upload(filePath, file, {
        cacheControl: "3600",
        upsert: true,
      });

    if (uploadError) throw uploadError;

    // Get Public URL
    const { data: publicUrlData } = supabase.storage
      .from("avatars")
      .getPublicUrl(filePath);
    const publicUrl = publicUrlData.publicUrl;

    // Update user avatar URL in the database
    const { error: updateError } = await supabase
      .from("users")
      .update({ avatar: publicUrl })
      .eq("user_id", userData.user_id);

    if (updateError) throw updateError;

    userData.avatar = publicUrl;
    showToast("Avatar updated successfully! ✨", "success");
  } catch (error) {
    console.error("Avatar upload error:", error);
    showToast(
      "Failed to upload avatar: " + (error.message || "Check Storage RLS"),
      "error"
    );
  }
}

// ==========================================
// Account Edit Mode
// ==========================================
function toggleEditMode() {
  editMode = !editMode;

  const displayNameInput = document.getElementById("displayName");
  const editBtn = document.getElementById("editAccountBtn");
  const actions = document.getElementById("accountActions");

  if (editMode) {
    // Enable edit mode
    if (displayNameInput) displayNameInput.disabled = false;
    if (editBtn) {
      editBtn.textContent = "❌ Cancel";
      editBtn.classList.add("btn-secondary");
      editBtn.classList.remove("btn-edit");
    }
    if (actions) actions.style.display = "flex";
    showToast("Edit mode enabled", "info");
  } else {
    // Disable edit mode
    if (displayNameInput) displayNameInput.disabled = true;
    if (editBtn) {
      editBtn.textContent = "✏️ Edit";
      editBtn.classList.remove("btn-secondary");
      editBtn.classList.add("btn-edit");
    }
    if (actions) actions.style.display = "none";

    // Reset values without saving
    loadUserData();
  }
}

function cancelEdit() {
  editMode = false;
  toggleEditMode();
}

async function saveAccountChanges() {
  const displayNameInput = document.getElementById("displayName");
  const displayName = displayNameInput ? displayNameInput.value.trim() : "";

  // Validation
  if (!displayName || displayName.length < 2) {
    showToast("Display name must be at least 2 characters", "error");
    return;
  }

  if (displayName.length > 100) {
    showToast("Display name must be less than 100 characters", "error");
    return;
  }

  try {
    const { error } = await supabase
      .from("users")
      .update({ display_name: displayName })
      .eq("user_id", userData.user_id);

    if (error) throw error;

    userData.display_name = displayName;
    showToast("Profile updated successfully! ✨", "success");
    editMode = false;
    toggleEditMode();
  } catch (error) {
    console.error("Save account error:", error);
    showToast("Failed to save changes", "error");
  }
}

// ==========================================
// Password Management
// ==========================================
function togglePasswordField(fieldId, toggleButton) {
  const passwordField = document.getElementById(fieldId);
  const eyeIcon = toggleButton.querySelector(".eye-icon");

  if (!passwordField || !eyeIcon) return;

  if (passwordField.type === "password") {
    passwordField.type = "text";
    // Change icon to 'eye-off' or 'slash' symbol (visually showing it's visible)
    eyeIcon.setAttribute("stroke-dasharray", "0 0 0 0 0 0"); // Quick way to remove a line or change appearance if using SVGs
    eyeIcon.setAttribute("stroke", "var(--primary)");
  } else {
    passwordField.type = "password";
    // Change icon back to 'eye' symbol
    eyeIcon.setAttribute("stroke-dasharray", "none");
    eyeIcon.setAttribute("stroke", "currentColor");
  }
}

function openPasswordModal() {
  document.getElementById("passwordModal").style.display = "flex";
  resetPasswordSteps();
}

function closePasswordModal() {
  document.getElementById("passwordModal").style.display = "none";
  resetPasswordSteps();
}

function resetPasswordSteps() {
  // Reset all password fields
  document.getElementById("currentPassword").value = "";
  document.getElementById("newPassword").value = "";
  document.getElementById("confirmNewPassword").value = "";

  // Show only first step
  document.getElementById("step1").style.display = "block";
  document.getElementById("step3").style.display = "none";
  document.getElementById("stepSuccess").style.display = "none";
}

async function verifyCurrentPassword() {
  const password = document.getElementById("currentPassword").value;

  if (!password) {
    showToast("Please enter your current password", "error");
    return;
  }

  if (password.length < 6) {
    showToast("Invalid password", "error");
    return;
  }

  try {
    const { error } = await supabase.auth.signInWithPassword({
      email: userData.email,
      password: password,
    });

    if (error) {
      showToast("Incorrect password", "error");
      return;
    }

    document.getElementById("step1").style.display = "none";
    document.getElementById("step3").style.display = "block";
    showToast("Verified! You can now change your password", "success");
  } catch (error) {
    console.error("Verify password error:", error);
    showToast("Error verifying password", "error");
  }
}

async function resetPassword() {
  const newPassword = document.getElementById("newPassword").value;
  const confirmPassword = document.getElementById("confirmNewPassword").value;

  // Validation
  if (!newPassword || newPassword.length < 6) {
    showToast("Password must be at least 6 characters", "error");
    return;
  }

  if (newPassword !== confirmPassword) {
    showToast("Passwords do not match", "error");
    return;
  }

  // Check password strength
  if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(newPassword)) {
    showToast(
      "Password must contain uppercase, lowercase, and numbers",
      "error"
    );
    return;
  }

  try {
    const { error } = await supabase.auth.updateUser({
      password: newPassword,
    });

    if (error) throw error;

    document.getElementById("step3").style.display = "none";
    document.getElementById("stepSuccess").style.display = "block";
    showToast("Password updated successfully! ✨", "success");

    // Auto close modal after 2 seconds
    setTimeout(() => {
      closePasswordModal();
    }, 2000);
  } catch (error) {
    console.error("Update password error:", error);
    showToast("Failed to update password", "error");
  }
}

// ==========================================
// Account Deletion
// ==========================================
function confirmDeleteAccount() {
  document.getElementById("deleteAccountModal").style.display = "flex";
}

function closeDeleteAccountModal() {
  document.getElementById("deleteAccountModal").style.display = "none";
  // Reset form
  if (document.getElementById("deleteAccountPassword")) {
    document.getElementById("deleteAccountPassword").value = "";
  }
  if (document.getElementById("deleteConfirmText")) {
    document.getElementById("deleteConfirmText").value = "";
  }
}

async function executeDeleteAccount() {
  const password = document.getElementById("deleteAccountPassword").value;
  const confirmText = document.getElementById("deleteConfirmText").value;

  // Validation
  if (!password) {
    showToast("Please enter your password", "error");
    return;
  }

  if (password.length < 6) {
    showToast("Invalid password format", "error");
    return;
  }

  if (confirmText !== "DELETE") {
    showToast('Type "DELETE" to confirm deletion', "error");
    return;
  }

  // Show confirmation before proceeding
  if (
    !confirm(
      "⚠️ This action CANNOT be undone. All your data will be permanently deleted. Are you absolutely sure?"
    )
  ) {
    return;
  }

  try {
    console.log("Starting account deletion process...");
    showToast("⏳ Deleting your account... Please wait.", "info");

    // Step 1: Verify password
    console.log("Step 1: Verifying password...");
    const { data: signInData, error: signInError } =
      await supabase.auth.signInWithPassword({
        email: userData.email,
        password: password,
      });

    if (signInError) {
      console.error("Password verification failed:", signInError);
      showToast("❌ Incorrect password", "error");
      return;
    }

    const authUserId = signInData.user.id;
    console.log("✅ Password verified, Auth ID:", authUserId);

    // Step 2: Call RPC function to delete all user data
    console.log("Step 2: Calling delete_user_account RPC function...");
    const { data: rpcResult, error: rpcError } = await supabase.rpc(
      "delete_user_account",
      {
        user_id_param: userData.user_id,
      }
    );

    if (rpcError) {
      console.error("RPC delete error:", rpcError);
      showToast("❌ Failed to delete account: " + rpcError.message, "error");
      return;
    }

    console.log("✅ RPC function executed successfully:", rpcResult);

    // Step 3: Delete avatar from storage
    console.log("Step 3: Deleting avatar from storage...");
    try {
      const { data: files } = await supabase.storage
        .from("avatars")
        .list(userData.user_id);

      if (files && files.length > 0) {
        const filePaths = files.map((f) => `${userData.user_id}/${f.name}`);
        const { error: removeError } = await supabase.storage
          .from("avatars")
          .remove(filePaths);

        if (removeError) {
          console.warn("Warning deleting avatar files:", removeError);
        } else {
          console.log("✅ Avatar files deleted");
        }
      }
    } catch (storageError) {
      console.warn("Warning with avatar storage:", storageError);
    }

    // Step 4: Sign out the user
    console.log("Step 4: Signing out user...");
    const { error: signOutError } = await supabase.auth.signOut();

    if (signOutError) {
      console.warn("Warning signing out:", signOutError);
    } else {
      console.log("✅ User signed out");
    }

    console.log("✅ Account deletion complete");
    showToast("🗑️ Account deleted successfully. Goodbye! 👋", "success");

    // Clear all storage
    localStorage.clear();
    sessionStorage.clear();

    // Redirect after delay
    setTimeout(() => {
      window.location.href = "login.html";
    }, 2000);
  } catch (error) {
    console.error("Unexpected error during account deletion:", error);
    showToast(
      "❌ An unexpected error occurred: " + (error.message || "Unknown error"),
      "error"
    );
  }
}

// ==========================================
// Toast Notifications
// ==========================================
function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;

  const backgroundColor =
    {
      success: "#00ff88",
      error: "#ff4444",
      info: "#00ccff",
    }[type] || "#00ccff";

  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 12px 20px;
    background: ${backgroundColor};
    color: #0a0e27;
    border-radius: 5px;
    font-weight: bold;
    z-index: 10000;
    animation: slideIn 0.3s ease-out;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  `;

  document.body.appendChild(toast);

  // Auto remove
  setTimeout(() => {
    toast.style.animation = "slideOut 0.3s ease-out";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ==========================================
// Expose Functions to Global Scope
// ==========================================
window.handleAvatarChange = handleAvatarChange;
window.toggleEditMode = toggleEditMode;
window.cancelEdit = cancelEdit;
window.saveAccountChanges = saveAccountChanges;
window.openPasswordModal = openPasswordModal;
window.closePasswordModal = closePasswordModal;
window.verifyCurrentPassword = verifyCurrentPassword;
window.resetPassword = resetPassword;
window.togglePasswordField = togglePasswordField;
window.handleAvatarChange = handleAvatarChange;
window.confirmDeleteAccount = confirmDeleteAccount;
window.closeDeleteAccountModal = closeDeleteAccountModal;
window.executeDeleteAccount = executeDeleteAccount;
window.showToast = showToast;
