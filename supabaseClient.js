
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// Dashboard → Project Settings → API → Project URL + anon/public key
const SUPABASE_URL = 'https://nbyvljvcqenorufrkfss.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5ieXZsanZjcWVub3J1ZnJrZnNzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjM1NDIwMzAsImV4cCI6MjA3OTExODAzMH0.E9Yvzp6CwKa7ycW4qFBm0ZZ3tx3dCyPEfyplLBo3_Vo';

// สร้าง client ตัวเดียวให้ทุกหน้า import ไปใช้
// เพิ่ม auth config เพื่อให้ session persist ดีขึ้น
export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    // ใช้ localStorage เพื่อเก็บ session (default)
    storage: window.localStorage,
    // Auto refresh token
    autoRefreshToken: true,
    // Persist session across browser tabs
    persistSession: true,
    // Detect session in URL (for OAuth redirects)
    detectSessionInUrl: true,
    // Flow type
    flowType: 'pkce'
  }
});