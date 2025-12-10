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
const checkFlagSecure = async function(shortId) {
    // 1. Check Authentication
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.user) {
        showNotification('⚠️ กรุณาเข้าสู่ระบบก่อนส่งคำตอบ', 'warning');
        return;
    }

    // 2. Get DOM elements
    const domCfg = (typeof FLAG_DOM_CONFIG !== 'undefined' ? FLAG_DOM_CONFIG[shortId] : {}) || {};
    const inputId = domCfg.input || `${shortId}Flag`;
    const successId = domCfg.success || `${shortId}Success`;
    const errorId = domCfg.error || `${shortId}Error`;

    const inputEl = document.getElementById(inputId);
    const successMsg = successId ? document.getElementById(successId) : null;
    const errorMsg = errorId ? document.getElementById(errorId) : null;

    if (!inputEl) {
        console.error(`Flag input not found: ${inputId}`);
        // showNotification('Error: Input field not found', 'error'); 
        // Commented out to prevent spam if config is missing
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
    // Note: ID_MAPPING and dbChallenges must be available globally or passed in
    // For now assuming they are on window or we need to fetch them
    // Ideally this logic should be robust. Assuming window.ID_MAPPING exists from challenge.js
    
    const mapping = window.ID_MAPPING || {};
    const targetTitle = mapping[shortId];
    const challenges = window.dbChallenges || [];
    const dbChallenge = challenges.find(c => c.title === targetTitle);

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
            if (!data.already_solved && window.userProgressDB) {
                window.userProgressDB[dbChallenge.challenge_id] = true;
                // Update score display if function exists
                if (typeof window.updatePointsDisplay === 'function') {
                     // Need to refresh user data essentially or increment locally
                     // Simplest is to reload page or re-fetch user, but we'll try to update local
                     // currentUser is not directly accessible here unless on window
                }
            }
             // Force a reload or UI update if needed, or let challenge.js handle it via event?
             // For now, let's keep it simple.

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

function sanitizeInput(input) {
    if (!input) return '';
    const temp = document.createElement('div');
    temp.textContent = input;
    return temp.innerHTML;
}

function validateFlagFormat(flag) {
    const flagPattern = /^secXplore\{[a-zA-Z0-9_\-@!#$%^&*()+=]+\}$/;
    return flagPattern.test(flag);
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

// Helper needed locally
function showNotification(message, type = 'success') {
    // If window.showNotification exists, use it, else basic alert or console
    if (typeof window.showNotification === 'function') {
        window.showNotification(message, type);
    } else {
        console.log(`[${type}] ${message}`);
        // Fallback implementation if challenge.js hasn't loaded it yet
    }
}

// ============================================
// EXPORTS & GLOBAL BINDING
// ============================================

// Bind to window for legacy onclick support if needed
window.checkFlagSecure = checkFlagSecure;
window.loadChallengesSecure = loadChallengesSecure;

// Export as module
export {
    checkFlagSecure,
    loadChallengesSecure,
    sanitizeInput,
    validateFlagFormat,
    checkClientRateLimit
};
