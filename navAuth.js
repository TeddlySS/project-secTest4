// navAuth.js
import { supabase } from './supabaseClient.js';

// ฟังก์ชันหลัก: ใช้ดึง user ปัจจุบัน + อัปเดต navbar
export async function setupNavUser() {
  const signInBtn = document.getElementById('navSignInBtn');
  const profileBtn = document.getElementById('navProfileBtn');
  const avatarImg = document.getElementById('navAvatar');
  const usernameSpan = document.getElementById('navUsername');
  const logoutBtn = document.getElementById('navLogoutBtn');

  // ถ้าหน้านี้ไม่มี nav (ไม่มี id เหล่านี้) ก็ไม่ต้องทำอะไร
  if (!signInBtn || !profileBtn) {
    return;
  }

  // ดึง user ปัจจุบันจาก Supabase
  const { data, error } = await supabase.auth.getUser();

  // ยังไม่ล็อกอิน → โชว์ปุ่ม Sign In
  if (error || !data?.user) {
    signInBtn.style.display = 'inline-flex';
    profileBtn.style.display = 'none';

    if (logoutBtn) logoutBtn.onclick = null; // กัน handler เก่าค้าง
    return;
  }

  const authUser = data.user;

  // ค่า default จาก auth
  let displayName =
    authUser.user_metadata?.full_name ||
    authUser.user_metadata?.name ||
    authUser.email?.split('@')[0] ||
    'Player';

  let avatarUrl =
    authUser.user_metadata?.avatar_url ||
    authUser.user_metadata?.picture ||
    null;

  // ลองดึงข้อมูลเพิ่มจาก table users (ถ้าเธอใช้จริง)
  try {
    const { data: profile, error: profileError } = await supabase
      .from('users')
      .select('display_name, username, avatar')
      .eq('email', authUser.email)
      .maybeSingle();

    if (!profileError && profile) {
      if (profile.display_name) displayName = profile.display_name;
      if (profile.username && !authUser.user_metadata?.full_name) {
        displayName = profile.username;
      }
      if (profile.avatar) avatarUrl = profile.avatar;
    }
  } catch (e) {
    console.warn('load profile for nav error:', e);
  }

  // ถ้าไม่มีรูปเลย ใช้ ui-avatars แทน
  if (!avatarUrl) {
    const encoded = encodeURIComponent(displayName || 'Player');
    avatarUrl = `https://ui-avatars.com/api/?name=${encoded}&size=200&background=00ff88&color=0a0e27&bold=true`;
  }

  // อัปเดต UI
  if (avatarImg) avatarImg.src = avatarUrl;
  if (usernameSpan) usernameSpan.textContent = displayName;

  signInBtn.style.display = 'none';
  profileBtn.style.display = 'inline-flex';

  // ✨ ผูกปุ่ม Logout ให้ตรงนี้
  if (logoutBtn) {
    logoutBtn.onclick = async (e) => {
      e.preventDefault();
      try {
        console.log('[navAuth] Logging out...');
        await supabase.auth.signOut();
        localStorage.removeItem('currentUser'); // ถ้า login.js เคยเก็บ
      } catch (err) {
        console.error('Error during logout:', err);
      }

      // รีเซ็ต navbar เป็นโหมด guest
      signInBtn.style.display = 'inline-flex';
      profileBtn.style.display = 'none';

      // เด้งกลับหน้า login
      window.location.href = 'login.html';
    };
  }
}

// เรียก auto ทุกครั้งที่ DOM โหลด (สำหรับหน้าที่ import navAuth.js)
document.addEventListener('DOMContentLoaded', () => {
  setupNavUser().catch((err) => {
    console.error('setupNavUser error:', err);
  });
});
