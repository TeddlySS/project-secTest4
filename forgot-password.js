// forgot-password.js
import { supabase } from './supabaseClient.js';
import { APP_CONFIG } from './config.js';

let currentStep = 1;
let userEmail = '';

// ==========================================
// UI Helpers
// ==========================================

function createParticles() {
    const container = document.getElementById('particles');
    if (!container) return;

    for (let i = 0; i < 50; i++) {
        const p = document.createElement('div');
        p.className = 'particle';
        p.style.left = Math.random() * 100 + '%';
        p.style.animationDelay = Math.random() * 15 + 's';
        p.style.animationDuration = (Math.random() * 10 + 10) + 's';
        container.appendChild(p);
    }
}

function showMessage(msg, type = 'info') {
    const messageDiv = document.getElementById('message');
    if (!messageDiv) {
        alert(msg);
        return;
    }

    messageDiv.textContent = msg;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';

    setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 5000);
}

function showStep(step) {
    currentStep = step;
    
    document.querySelectorAll('.step').forEach(s => {
        s.classList.remove('active');
    });
    
    const stepElement = document.getElementById(`step${step}`);
    if (stepElement) {
        stepElement.classList.add('active');
    }

    updateProgressBar();
}

function updateProgressBar() {
    const progressBar = document.querySelector('.progress-bar');
    if (!progressBar) return;

    const progress = (currentStep / 3) * 100;
    progressBar.style.width = progress + '%';
}

// ==========================================
// Step 1: Request Reset Link
// ==========================================

async function handleRequestReset(e) {
    e.preventDefault();

    const emailInput = document.getElementById('emailInput');
    const submitBtn = document.getElementById('requestBtn');

    if (!emailInput || !submitBtn) return;

    const email = emailInput.value.trim();

    if (!email) {
        showMessage('กรุณากรอกอีเมล', 'error');
        return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showMessage('รูปแบบอีเมลไม่ถูกต้อง', 'error');
        return;
    }

    submitBtn.disabled = true;
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'กำลังส่ง...';

    try {
        // Check if email exists in users table
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('email')
            .eq('email', email)
            .single();

        if (userError || !user) {
            showMessage('ไม่พบอีเมลนี้ในระบบ', 'error');
            return;
        }

        // Send password reset email
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: `${APP_CONFIG.BASE_URL}/forgot-password.html?step=2`,
        });

        if (error) {
            console.error('Reset password error:', error);
            showMessage('ไม่สามารถส่งอีเมลรีเซ็ตรหัสผ่านได้: ' + error.message, 'error');
            return;
        }

        userEmail = email;
        showMessage('ส่งลิงก์รีเซ็ตรหัสผ่านไปยังอีเมลของคุณแล้ว', 'success');
        
        setTimeout(() => {
            showStep(2);
        }, 2000);
    } catch (err) {
        console.error('Request reset error:', err);
        showMessage('เกิดข้อผิดพลาดในการส่งอีเมล', 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

// ==========================================
// Step 2: Waiting for Email Confirmation
// ==========================================

function resendResetEmail() {
    if (!userEmail) {
        showMessage('กรุณากรอกอีเมลใหม่อีกครั้ง', 'error');
        showStep(1);
        return;
    }

    handleRequestReset({ preventDefault: () => {} });
}

// ==========================================
// Step 3: Set New Password
// ==========================================

async function handleSetNewPassword(e) {
    e.preventDefault();

    const newPasswordInput = document.getElementById('newPassword');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const submitBtn = document.getElementById('resetBtn');

    if (!newPasswordInput || !confirmPasswordInput || !submitBtn) return;

    const newPassword = newPasswordInput.value.trim();
    const confirmPassword = confirmPasswordInput.value.trim();

    if (!newPassword || !confirmPassword) {
        showMessage('กรุณากรอกรหัสผ่านให้ครบ', 'error');
        return;
    }

    if (newPassword.length < 8) {
        showMessage('รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร', 'error');
        return;
    }

    if (newPassword !== confirmPassword) {
        showMessage('รหัสผ่านไม่ตรงกัน', 'error');
        return;
    }

    submitBtn.disabled = true;
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'กำลังบันทึก...';

    try {
        // Update password using Supabase Auth
        const { error } = await supabase.auth.updateUser({
            password: newPassword
        });

        if (error) {
            console.error('Update password error:', error);
            showMessage('ไม่สามารถเปลี่ยนรหัสผ่านได้: ' + error.message, 'error');
            return;
        }

        showMessage('เปลี่ยนรหัสผ่านสำเร็จ! กำลังนำคุณไปหน้า Login...', 'success');
        
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 2000);
    } catch (err) {
        console.error('Set new password error:', err);
        showMessage('เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน', 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

// ==========================================
// Password Strength Indicator
// ==========================================

function checkPasswordStrength() {
    const passwordInput = document.getElementById('newPassword');
    const strengthBar = document.getElementById('strengthBar');
    const strengthText = document.getElementById('strengthText');

    if (!passwordInput || !strengthBar || !strengthText) return;

    const password = passwordInput.value;
    let strength = 0;

    if (password.length >= 8) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;

    const strengthLevels = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'];
    const strengthColors = ['#ff4444', '#ff8800', '#ffbb33', '#00C851', '#007E33'];

    strengthBar.style.width = (strength * 25) + '%';
    strengthBar.style.backgroundColor = strengthColors[strength] || strengthColors[0];
    strengthText.textContent = strengthLevels[strength] || strengthLevels[0];
    strengthText.style.color = strengthColors[strength] || strengthColors[0];
}

// ==========================================
// Password Visibility Toggle
// ==========================================

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    if (!input) return;

    const type = input.type === 'password' ? 'text' : 'password';
    input.type = type;

    const icon = input.nextElementSibling?.querySelector('i');
    if (icon) {
        icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    }
}

// ==========================================
// Check URL Parameters
// ==========================================

function checkUrlParameters() {
    const urlParams = new URLSearchParams(window.location.search);
    const step = urlParams.get('step');
    const accessToken = urlParams.get('access_token');
    const type = urlParams.get('type');

    // If user clicked reset link in email
    if (type === 'recovery' && accessToken) {
        showStep(3);
        return;
    }

    // If step parameter exists
    if (step) {
        const stepNumber = parseInt(step);
        if (stepNumber >= 1 && stepNumber <= 3) {
            showStep(stepNumber);
        }
    }
}

// ==========================================
// Session Check
// ==========================================

async function checkSession() {
    const { data: { session } } = await supabase.auth.getSession();
    
    if (session) {
        // User is logged in, check if they're in recovery mode
        const urlParams = new URLSearchParams(window.location.search);
        const type = urlParams.get('type');
        
        if (type === 'recovery') {
            showStep(3);
        }
    }
}

// ==========================================
// Initialize
// ==========================================

document.addEventListener('DOMContentLoaded', async () => {
    createParticles();
    checkUrlParameters();
    await checkSession();

    // Bind form events
    const requestForm = document.getElementById('requestResetForm');
    if (requestForm) {
        requestForm.addEventListener('submit', handleRequestReset);
    }

    const resetForm = document.getElementById('setPasswordForm');
    if (resetForm) {
        resetForm.addEventListener('submit', handleSetNewPassword);
    }

    // Password strength check
    const newPasswordInput = document.getElementById('newPassword');
    if (newPasswordInput) {
        newPasswordInput.addEventListener('input', checkPasswordStrength);
    }

    // Back to login button
    const backBtn = document.querySelector('.back-to-login');
    if (backBtn) {
        backBtn.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = 'login.html';
        });
    }
});

// ==========================================
// Make functions global
// ==========================================

window.showStep = showStep;
window.resendResetEmail = resendResetEmail;
window.togglePasswordVisibility = togglePasswordVisibility;