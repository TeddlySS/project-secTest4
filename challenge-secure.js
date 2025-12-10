// challenge-secure.js
// SECURE VERSION - Replaces insecure checkFlag() function

import { supabase } from './supabaseClient.js';

// ============================================
// SECURE FLAG VALIDATION
// ============================================

/**
 * Secure flag validation - calls server-side Edge Function
 * NEVER exposes actual flag to client
 */
window.checkFlagSecure = async function(shortId) {
    // 1. Check Authentication
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.user) {
        showNotification('⚠️ กรุณาเข้าสู่ระบบก่อนส่งคำตอบ', 'warning');
        return;
    }

    // 2. Get DOM elements
    const domCfg = FLAG_DOM_CONFIG[shortId] || {};
    const inputId = domCfg.input || `${shortId}Flag`;
    const successId = domCfg.success || `${shortId}Success`;
    const errorId = domCfg.error || `${shortId}Error`;

    const inputEl = document.getElementById(inputId);
    const successMsg = successId ? document.getElementById(successId) : null;
    const errorMsg = errorId ? document.getElementById(errorId) : null;

    if (!inputEl) {
        console.error(`Flag input not found: ${inputId}`);
        showNotification('Error: Input field not found', 'error');
        return;
    }

    const userFlag = inputEl.value.trim();
    if (!userFlag) {
        if (errorMsg) {
            errorMsg.style.display = 'block';
            errorMsg.textContent = '⚠️ กรุณาใส่ Flag';
            setTimeout(() => errorMsg.style.display = 'none', 3000);
        }
        return;
    }

    // 3. Get challenge_id from mapping
    const targetTitle = ID_MAPPING[shortId];
    const dbChallenge = dbChallenges.find(c => c.title === targetTitle);

    if (!dbChallenge) {
        console.error(`Challenge not found: ${targetTitle}`);
        showNotification('Error: Challenge not found', 'error');
        return;
    }

    try {
        // 4. Show loading state
        if (inputEl) inputEl.disabled = true;
        showNotification('🔍 กำลังตรวจสอบ...', 'info');

        // 5. Call SECURE Edge Function for validation
        const { data, error } = await supabase.functions.invoke('validate-flag', {
            body: {
                challenge_id: dbChallenge.challenge_id,
                flag: userFlag
            }
        });

        if (error) {
            throw error;
        }

        if (!data.success) {
            throw new Error(data.error || 'Validation failed');
        }

        // 6. Update UI based on result
        if (data.is_correct) {
            if (successMsg) {
                successMsg.style.display = 'block';
                if (data.already_solved) {
                    successMsg.innerHTML = `🎉 ถูกต้อง! (คุณทำข้อนี้ไปแล้ว)`;
                } else {
                    successMsg.innerHTML = `
                        🎉 ถูกต้อง! +${data.points_earned} คะแนน<br>
                        <small style="color: var(--gray);">
                            (Hints used: ${data.hints_used}, Penalty: -${data.penalty})
                        </small>
                    `;
                }
            }
            if (errorMsg) errorMsg.style.display = 'none';
            
            showNotification(
                data.already_solved 
                    ? 'Challenge already solved!' 
                    : `+${data.points_earned} points!`, 
                'success'
            );

            // Update local state
            if (!data.already_solved) {
                userProgressDB[dbChallenge.challenge_id] = true;
                if (currentUser) {
                    currentUser.score = (currentUser.score || 0) + data.points_earned;
                }
                updatePointsDisplay();
            }

        } else {
            // Wrong flag
            if (successMsg) successMsg.style.display = 'none';
            if (errorMsg) {
                errorMsg.style.display = 'block';
                errorMsg.textContent = '❌ Flag ไม่ถูกต้อง';
                setTimeout(() => errorMsg.style.display = 'none', 3000);
            }
            showNotification('Flag ไม่ถูกต้อง', 'error');
        }

    } catch (err) {
        console.error('Flag validation error:', err);
        
        // Handle rate limiting
        if (err.message?.includes('Rate limit')) {
            showNotification('⏳ กรุณารอสักครู่ก่อนลองอีกครั้ง', 'warning');
        } else {
            showNotification('เกิดข้อผิดพลาดในการตรวจสอบ', 'error');
        }
        
        if (errorMsg) {
            errorMsg.style.display = 'block';
            errorMsg.textContent = '❌ ' + (err.message || 'เกิดข้อผิดพลาด');
            setTimeout(() => errorMsg.style.display = 'none', 5000);
        }

    } finally {
        // Re-enable input
        if (inputEl) inputEl.disabled = false;
    }
};

// ============================================
// SECURE CHALLENGE DATA LOADING
// ============================================

/**
 * Load challenges WITHOUT flags
 * Flags are NEVER sent to client
 */
async function loadChallengesSecure() {
    try {
        // Only select necessary fields - NEVER include 'flag' column
        const { data: challenges, error } = await supabase
            .from('challenges')
            .select(`
                challenge_id,
                code,
                title,
                description,
                category,
                difficulty,
                score_base,
                interactive_id,
                is_active,
                visibility,
                tags,
                challenge_url
            `)
            .eq('is_active', true)
            .order('difficulty', { ascending: true });

        if (error) throw error;

        return challenges || [];

    } catch (err) {
        console.error('Error loading challenges:', err);
        showNotification('ไม่สามารถโหลดโจทย์ได้', 'error');
        return [];
    }
}

// ============================================
// INPUT SANITIZATION
// ============================================

/**
 * Sanitize user input to prevent XSS
 */
function sanitizeInput(input) {
    if (!input) return '';
    
    // Remove any HTML tags
    const temp = document.createElement('div');
    temp.textContent = input;
    return temp.innerHTML;
}

/**
 * Validate flag format before submission
 */
function validateFlagFormat(flag) {
    // Check basic format: secXplore{...}
    const flagPattern = /^secXplore\{[a-zA-Z0-9_\-@!#$%^&*()+=]+\}$/;
    return flagPattern.test(flag);
}

// ============================================
// ANTI-DEBUGGING MEASURES
// ============================================

/**
 * Basic anti-debugging - detects if DevTools is open
 * Note: This is NOT foolproof but adds a layer of deterrence
 */
function initAntiDebug() {
    // Detect DevTools
    const devtools = /./;
    devtools.toString = function() {
        this.opened = true;
    };

    // Check regularly
    setInterval(() => {
        console.log('%c', devtools);
        if (devtools.opened) {
            // Don't block completely, just warn
            console.clear();
            console.log('%c⚠️ Developer Tools Detected', 
                'color: #ff0000; font-size: 20px; font-weight: bold;');
            console.log('%cFor security reasons, please close developer tools when solving challenges.',
                'color: #ffaa00; font-size: 14px;');
        }
    }, 1000);

    // Disable right-click context menu on challenge content
    document.addEventListener('contextmenu', (e) => {
        if (e.target.closest('.challenge-card')) {
            e.preventDefault();
            showNotification('⚠️ Right-click disabled on challenges', 'warning');
        }
    });

    // Detect common debugging shortcuts
    document.addEventListener('keydown', (e) => {
        // F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
        if (
            e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J')) ||
            (e.ctrlKey && e.key === 'U')
        ) {
            // Don't block completely, just warn
            console.log('%c⚠️ Developer Tools Shortcut Detected', 
                'color: #ff0000; font-size: 16px;');
        }
    });
}

// ============================================
// CONTENT SECURITY POLICY HELPER
// ============================================

/**
 * Add security headers via meta tags
 * Note: Best practice is to set these on server (Netlify headers)
 */
function initSecurityHeaders() {
    // Add CSP meta tag
    const csp = document.createElement('meta');
    csp.httpEquiv = 'Content-Security-Policy';
    csp.content = `
        default-src 'self';
        script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com;
        style-src 'self' 'unsafe-inline';
        img-src 'self' data: https:;
        connect-src 'self' https://*.supabase.co;
        font-src 'self' data:;
        frame-ancestors 'none';
    `.replace(/\s+/g, ' ').trim();
    document.head.appendChild(csp);

    // Add X-Frame-Options
    const xFrame = document.createElement('meta');
    xFrame.httpEquiv = 'X-Frame-Options';
    xFrame.content = 'DENY';
    document.head.appendChild(xFrame);
}

// ============================================
// RATE LIMITING (CLIENT-SIDE)
// ============================================

const rateLimitStore = {};

function checkClientRateLimit(challengeId) {
    const now = Date.now();
    const key = `challenge_${challengeId}`;
    
    if (!rateLimitStore[key]) {
        rateLimitStore[key] = { attempts: [], lastReset: now };
    }

    const store = rateLimitStore[key];
    
    // Remove attempts older than 5 minutes
    store.attempts = store.attempts.filter(time => now - time < 5 * 60 * 1000);
    
    // Check if exceeded limit
    if (store.attempts.length >= 5) {
        const oldestAttempt = Math.min(...store.attempts);
        const waitTime = Math.ceil((5 * 60 * 1000 - (now - oldestAttempt)) / 1000);
        return {
            allowed: false,
            waitTime: waitTime
        };
    }

    // Add current attempt
    store.attempts.push(now);
    
    return { allowed: true };
}

// ============================================
// INITIALIZATION
// ============================================

// Initialize security measures when DOM loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initSecurityHeaders();
        initAntiDebug();
    });
} else {
    initSecurityHeaders();
    initAntiDebug();
}

// Export for use in other files
export {
    checkFlagSecure,
    loadChallengesSecure,
    sanitizeInput,
    validateFlagFormat,
    checkClientRateLimit
};
