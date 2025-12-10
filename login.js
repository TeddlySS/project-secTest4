// login.js
import { supabase } from "./supabaseClient.js";
import { setupNavUser } from "./navAuth.js";

// ---------- UI helper: particles ----------
function createParticles() {
  const container = document.getElementById("particles");
  if (!container) return;

  for (let i = 0; i < 50; i++) {
    const p = document.createElement("div");
    p.className = "particle";
    p.style.left = Math.random() * 100 + "%";
    p.style.animationDelay = Math.random() * 15 + "s";
    p.style.animationDuration = Math.random() * 10 + 10 + "s";
    container.appendChild(p);
  }
}

function showMessage(msg) {
  alert(msg);
}

// ---------- แปลง username → email (ถ้า login เป็น username) ----------
async function resolveLoginToEmail(loginValue) {
  if (loginValue.includes("@")) return loginValue;

  try {
    const { data, error } = await supabase
      .from("users")
      .select("email")
      .eq("username", loginValue)
      .single();

    if (error || !data) {
      throw new Error("ไม่พบบัญชีผู้ใช้สำหรับ username นี้");
    }

    return data.email;
  } catch (err) {
    console.error("resolveLoginToEmail error:", err);
    throw err;
  }
}

// ---------- Login ด้วย email/username + password ----------

async function handleLogin(e) {
  e.preventDefault();

  const loginForm = document.getElementById("loginForm");
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");
  const loginBtn = document.querySelector(".login-btn");

  if (!loginForm || !usernameInput || !passwordInput || !loginBtn) return;

  const loginValue = usernameInput.value.trim();
  const password = passwordInput.value.trim();

  if (!loginValue || !password) {
    showMessage("กรุณากรอกข้อมูลให้ครบ");
    return;
  }

  loginBtn.disabled = true;
  const originalText = loginBtn.textContent;
  loginBtn.textContent = "Signing in...";

  try {
    const email = await resolveLoginToEmail(loginValue);
    console.log("Attempting login with email:", email);

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      console.error("Login error:", error);
      if (error.message.includes("Invalid login credentials")) {
        showMessage("อีเมลหรือรหัสผ่านไม่ถูกต้อง");
      } else {
        showMessage(error.message || "เข้าสู่ระบบไม่สำเร็จ");
      }
      return;
    }

    if (!data.session || !data.user) {
      showMessage("เข้าสู่ระบบไม่สำเร็จ กรุณาลองใหม่อีกครั้ง");
      return;
    }

    console.log("Login successful:", data.user.id);
    // ตรวจสอบว่าอีเมลได้รับการยืนยันหรือไม่
    if (data.user && !data.user.email_confirmed_at) {
      showMessage("กรุณายืนยันอีเมลก่อนเข้าสู่ระบบ\n\nตรวจสอบอีเมลของคุณและคลิกลิงก์ยืนยัน");
      
      // ถามว่าต้องการส่งอีเมลใหม่หรือไม่
      if (confirm("ต้องการส่งอีเมลยืนยันใหม่หรือไม่?")) {
        try {
          const { error: resendError } = await supabase.auth.resend({
            type: 'signup',
            email: email
          });
          
          if (resendError) {
            showMessage("ไม่สามารถส่งอีเมลได้: " + resendError.message);
          } else {
            showMessage("ส่งอีเมลยืนยันใหม่แล้ว กรุณาตรวจสอบอีเมลของคุณ");
          }
        } catch (err) {
          console.error("Resend email error:", err);
        }
      }
      
      await supabase.auth.signOut();
      return;
    }
    // อ่านข้อมูล user จากตาราง users
    const { data: userData, error: fetchError } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (fetchError || !userData) {
      console.error("Fetch user data error:", fetchError);
      showMessage("เข้าสู่ระบบสำเร็จ แต่ไม่สามารถโหลดข้อมูลผู้ใช้ได้");
      return;
    }

    // เก็บข้อมูล user ไว้ใช้ต่อ
    localStorage.setItem("currentUser", JSON.stringify(userData));

    // redirect ไปหน้า home
    window.location.href = "home.html";
  } catch (err) {
    console.error("handleLogin error:", err);
    showMessage(err.message || "เกิดข้อผิดพลาดในการเข้าสู่ระบบ");
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = originalText;
  }
}

function togglePasswordVisibility(inputId, buttonId) {
  const input = document.getElementById(inputId);
  const button = document.getElementById(buttonId);

  if (!input || !button) return;

  button.addEventListener("click", () => {
    const type = input.type === "password" ? "text" : "password";
    input.type = type;
    // Toggles visibility of eye icons based on input type
    button.querySelector(".eye-closed").style.display =
      type === "password" ? "block" : "none";
    button.querySelector(".eye-open").style.display =
      type === "password" ? "none" : "block";
  });
}

// ---------- Google OAuth ----------
async function signInWithGoogle() {
  const googleBtn = document.getElementById("googleSignInBtn");
  if (!googleBtn) return;

  googleBtn.disabled = true;
  const originalHtml = googleBtn.innerHTML;
  googleBtn.innerHTML = "Connecting to Google...";

  try {
    const { error } = await supabase.auth.signInWithOAuth({
      provider: "google",
      options: {
        redirectTo: "https://secxplore.space/home.html",
      },
    });

    if (error) {
      console.error("Google OAuth error:", error);
      showMessage(
        "ไม่สามารถเชื่อมต่อ Google ได้: " + (error.message || "unknown error")
      );
    }
  } catch (err) {
    console.error("signInWithGoogle error:", err);
    showMessage("เกิดข้อผิดพลาดในการเชื่อมต่อ Google");
  } finally {
    googleBtn.disabled = false;
    googleBtn.innerHTML = originalHtml;
  }
}

// ---------- ✅ LOGOUT FUNCTION (NEW) ----------
export async function logout() {
  try {
    // Sign out from Supabase
    const { error } = await supabase.auth.signOut();

    if (error) {
      console.error("Logout error:", error);
      showMessage("Error logging out: " + error.message);
      return;
    }

    // Clear local storage
    localStorage.removeItem("currentUser");

    // Redirect to login
    window.location.href = "login.html";
  } catch (err) {
    console.error("logout error:", err);
    showMessage("Failed to logout");
  }
}

// ---------- เช็ค session เดิม (MODIFIED) ----------
async function checkExistingSession() {
  try {
    const { data, error } = await supabase.auth.getSession();

    if (error) {
      console.error("Session check error:", error);
      return;
    }

    // ✅ REMOVED auto-redirect - let user choose to login/logout
    if (data.session) {
      console.log("Existing session found");
    }
  } catch (err) {
    console.error("checkExistingSession error:", err);
  }
}

// ---------- Ready ----------
document.addEventListener("DOMContentLoaded", () => {
  createParticles();

  togglePasswordVisibility("password", "togglePassword");

  const loginForm = document.getElementById("loginForm");
  if (loginForm) loginForm.addEventListener("submit", handleLogin);

  const googleBtn = document.getElementById("googleSignInBtn");
  if (googleBtn) {
    googleBtn.addEventListener("click", (e) => {
      e.preventDefault();
      signInWithGoogle();
    });
  }

  checkExistingSession();
});
