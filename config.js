// config.js
const ORIGIN =
  typeof window !== 'undefined' && window.location?.origin
    ? window.location.origin
    : 'https://secxplore.space';

export const APP_CONFIG = {
  // Base URL ของเว็บ (ใช้ origin ปัจจุบัน จะได้ใช้ได้ทั้ง localhost และบน Netlify)
  BASE_URL: ORIGIN,

  // path ของแต่ละหน้า
  PAGES: {
    HOME: '/home.html',
    LOGIN: '/login.html',
    REGISTER: '/register.html',
    CHALLENGE: '/challenge.html',
    PROFILE: '/profile.html',
    LEADERBOARD: '/leaderboard.html',
    ADMIN: '/admin.html',
    FORGOT_PASSWORD: '/forgot-password.html',
  },

  // URL ที่ Supabase จะ redirect กลับมาหลัง Google OAuth (ไปหน้าโจทย์)
  OAUTH_REDIRECT: ORIGIN + '/challenge.html',

  // config อื่น ๆ เผื่อใช้
  MAX_RETRIES: 3,
};

// Helper functions
export function getFullUrl(path) {
  return APP_CONFIG.BASE_URL + path;
}

export function getOAuthRedirect() {
  return APP_CONFIG.OAUTH_REDIRECT;
}

export function getPageUrl(pageName) {
  return APP_CONFIG.BASE_URL + (APP_CONFIG.PAGES[pageName] || pageName);
}
