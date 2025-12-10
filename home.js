import { supabase } from "./supabaseClient.js";
import { setupNavUser } from "./navAuth.js";

const hamburgerBtn = document.getElementById("hamburgerBtn");
const navContainer = document.querySelector(".nav-container");

if (hamburgerBtn && navContainer) {
  hamburgerBtn.addEventListener("click", () => {
    // บรรทัดนี้จะเพิ่ม/ลบ คลาส 'menu-active' ให้กับ nav-container
    navContainer.classList.toggle("menu-active");
  });
}
// ==========================================
// Particle Generation
// ==========================================
function createParticles() {
  const particlesContainer = document.getElementById("particles");
  if (!particlesContainer) return;

  for (let i = 0; i < 100; i++) {
    const particle = document.createElement("div");
    particle.className = "particle";
    particle.style.left = Math.random() * 100 + "%";
    particle.style.animationDelay = Math.random() * 15 + "s";
    particle.style.animationDuration = Math.random() * 10 + 10 + "s";
    particlesContainer.appendChild(particle);
  }
}

// ==========================================
// Stats Animation
// ==========================================
function animateValue(element, start, end, duration) {
  if (!element) return;

  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    const value = Math.floor(progress * (end - start) + start);

    // FIX: Removed the conditional check that added '+'
    element.textContent = value;

    if (progress < 1) {
      window.requestAnimationFrame(step);
    }
  };
  window.requestAnimationFrame(step);
}

// ==========================================
// Database and Stats Loading
// ==========================================
// home.js (REPLACE loadRealStats function)
async function loadRealStats() {
  try {
    // 1. Count Active Challenges
    const { count: challengesCount, error: challengesError } = await supabase
      .from("challenges")
      .select("*", { count: "exact", head: true })
      .eq("is_active", true); // นับเฉพาะ Challenges ที่ Active

    if (challengesError) throw challengesError;

    // 2. Count Active Users
    const { count: usersCount, error: usersError } = await supabase
      .from("users")
      .select("*", { count: "exact", head: true })
      .eq("status", "active"); // นับเฉพาะ Users ที่ Active (สมมติว่ามีคอลัมน์ status)

    if (usersError) throw usersError;

    // 3. Count Correct Submissions (Solves)
    const { count: solvesCount, error: solvesError } = await supabase
      .from("submissions")
      .select("*", { count: "exact", head: true })
      .eq("is_correct", true);

    if (solvesError) throw solvesError;

    // 4. Count Categories (Distinct)
    // ดึงคอลัมน์ category ทั้งหมดมา
    const { data: categoriesData, error: catError } = await supabase
      .from("challenges")
      .select("category");

    let categoriesCount = 0;
    if (!catError && categoriesData) {
      // ใช้ Set เพื่อหาจำนวน Categories ที่ไม่ซ้ำกัน
      const uniqueCategories = new Set(
        categoriesData.map((item) => item.category)
      ).size;
      categoriesCount = uniqueCategories;
    }

    return {
      totalChallenges: challengesCount || 0,
      totalUsers: usersCount || 0,
      totalSolves: solvesCount || 0,
      totalCategories: categoriesCount || 0, // ส่งค่า Categories ที่ไม่ซ้ำกันออกไป
    };
  } catch (error) {
    console.error("Error loading stats:", error);
    return {
      totalChallenges: 0,
      totalUsers: 0,
      totalSolves: 0,
      totalCategories: 0,
    };
  }
}

// Intersection Observer for Stats Animation
const observerOptions = {
  threshold: 0.5,
};

async function initializeStatsAnimation() {
  const statsSection = document.querySelector(".stats-section");
  if (!statsSection) return;

  // Load real stats
  const stats = await loadRealStats();

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        animateValue(
          document.getElementById("totalChallenges"),
          0,
          stats.totalChallenges,
          2000
        );

        // สำหรับ Users และ Solves เรายังคงบวกเครื่องหมาย '+' เข้าไป
        animateValue(
          document.getElementById("totalUsers"),
          0,
          stats.totalUsers,
          2000
        );
        animateValue(
          document.getElementById("totalSolves"),
          0,
          stats.totalSolves,
          2000
        );

        // อัปเดต: ใช้ ID ใหม่สำหรับ Categories และไม่ต้องมี '+'
        animateValue(
          document.getElementById("totalCategories"),
          0,
          stats.totalCategories,
          2000
        );

        observer.unobserve(statsSection);
      }
    });
  }, observerOptions);

  observer.observe(statsSection);
}

// ==========================================
// Auth UI Hiding and CTA Logic (FIXED)
// ==========================================
async function handleInitialAuthUI() {
  // Check session status immediately
  const {
    data: { session },
  } = await supabase.auth.getSession();
  const user = session?.user;

  const signInBtn = document.getElementById("navSignInBtn");
  const profileBtn = document.getElementById("navProfileBtn");
  const heroCtaButton = document.getElementById("heroCtaButton"); // ID added in HTML

  if (user) {
    // --- Navbar Fix: User is logged in ---
    // Reveal profile link, remove hidden class
    if (profileBtn) profileBtn.classList.remove("loading-hidden");
    if (signInBtn) signInBtn.style.display = "none";

    // --- CTA Button Fix: Change link to Challenges ---
    if (heroCtaButton) {
      heroCtaButton.href = "challenge.html";
    }
  } else {
    // --- Navbar Fix: User is logged out ---
    // Reveal sign-in button, remove hidden class
    if (signInBtn) signInBtn.classList.remove("loading-hidden");
    if (profileBtn) profileBtn.style.display = "none";

    // --- CTA Button Fix: Ensure link remains Login (default) ---
    // Default HTML link is already login.html, but we ensure it here
    if (heroCtaButton) {
      heroCtaButton.href = "login.html";
    }
  }
}

// ==========================================
// Initialize
// ==========================================
document.addEventListener("DOMContentLoaded", async () => {
  createParticles();

  // 1. Run the auth check and UI update immediately (fixes flicker and CTA link)
  await handleInitialAuthUI();

  // 2. Call the external setupNavUser to fetch profile details (username, avatar)
  await setupNavUser();

  await initializeStatsAnimation();
});
