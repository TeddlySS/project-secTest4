// ============================================
// 1. IMPORTS & GLOBAL STATE
// ============================================
import { supabase } from './supabaseClient.js';
import { setupNavUser } from './navAuth.js';

let currentUser = null;
let dbChallenges = []; // เก็บข้อมูลโจทย์ทั้งหมดจาก DB เพื่อลด Request
let userProgressDB = {}; // เก็บสถานะว่า user ทำข้อไหนไปแล้วบ้าง

// ค่าปรับคะแนนต่อ 1 Hint
const HINT_PENALTY = 10;

// Mapping เชื่อมโยงชื่อ ID ใน HTML (shortId) ให้ตรงกับ Title ใน Database
const ID_MAPPING = {
    'sqlInjection': 'SQL Injection Login Bypass',
    'cmdInjection': 'Command Injection Shell',
    'xssStealer': 'XSS Cookie Stealer',

    'multiCipher': 'Multi-Layer Cipher',
    'xorBrute': 'XOR Brute Force',
    'rsaAttack': 'RSA Small Exponent Attack',

    'birthdayExif': 'Hidden Birthday Message',
    'geoLocation': 'Geolocation Mystery',
    'stegoFlag': 'Steganography Battlefield',

    'packetBasic': 'Packet Sniffer Basic',
    'dnsTunnel': 'DNS Tunneling Extract',
    'arpSpoof': 'ARP Spoofing Attack',

    'asmPassword': 'Assembly Password Check',
    'crackme': 'Binary Crackme',
    'obfuscated': 'Obfuscated Code Analysis',

    'apkStrings': 'APK String Analysis',
    'rootBypass': 'Root Detection Bypass',
    'sslPinning': 'SSL Pinning Challenge',
};
const FLAG_DOM_CONFIG = {
    sqlInjection: { input: 'sqlInjectionFlag', success: 'sqlSuccess', error: 'sqlError' },
    cmdInjection: { input: 'cmdInjectionFlag', success: 'cmdSuccess', error: 'cmdError' },
    xssStealer:  { input: 'xssStealerFlag', success: 'xssSuccess', error: 'xssError' },

    multiCipher: { input: 'multiCipherFlag', success: 'multiSuccess', error: 'multiError' },
    xorBrute:    { input: 'xorKnownFlag', success: 'xorSuccess', error: 'xorError' },
    rsaAttack:   { input: 'rsaAttackFlag', success: 'rsaSuccess', error: 'rsaError' },

    birthdayExif:{ input: 'birthdayExifFlag', success: 'birthdaySuccess', error: 'birthdayError' },
    geoLocation: { input: 'geoLocationFlag',  success: 'geoSuccess',      error: 'geoError' },
    stegoFlag:   { input: 'stegoFlagFlag',    success: 'stegoSuccess',    error: 'stegoError' },

    packetBasic: { input: 'packetBasicFlag',  success: 'packetSuccess',   error: 'packetError' },
    dnsTunnel:   { input: 'dnsTunnelFlag',    success: 'dnsSuccess',      error: 'dnsError' },
    arpSpoof:    { input: 'arpSpoofFlag',     success: 'arpSuccess',      error: 'arpError' },

    asmPassword: { input: 'asmPasswordFlag',  success: 'asmSuccess',      error: 'asmError' },
    crackme:     { input: 'crackmeFlag',      success: 'crackmeSuccess',  error: 'crackmeError' },
    obfuscated:  { input: 'obfuscatedFlag',   success: 'obfuscatedSuccess', error: 'obfuscatedError' },
    
    apkStrings:  { input: 'apkAnalysisFlag',  success: 'apkSuccess',      error: 'apkError' },
    rootBypass:  { input: 'rootDetectionFlag', success: 'rootSuccess',    error: 'rootError' },
    sslPinning:  { input: 'sslPinningFlag',   success: 'sslPinSuccess',   error: 'sslPinError' },
};

// mapping prefix ของ hint → shortId ของ challenge
const LEGACY_MAP = {
    'sql': 'sqlInjection',
    'cmd': 'cmdInjection',
    'xss': 'xssStealer',
    'multi': 'multiCipher',
    'xor': 'xorBrute',
    'rsa': 'rsaAttack',
    'birthday': 'birthdayExif',
    'geo': 'geoLocation',
    'stego': 'stegoFlag',
    'packet': 'packetBasic',
    'dns': 'dnsTunnel',
    'arp': 'arpSpoof',
    'asm': 'asmPassword',
    'crackme': 'crackme', 
    'obfuscated': 'obfuscated', 
    'apk': 'apkStrings',
    'root': 'rootBypass',
    'sslPin': 'sslPinning',
};

// ============================================
document.addEventListener('DOMContentLoaded', async () => {
    console.log("🚀 Initializing Challenge System...");
    
    // 1. Setup Navbar & Auth
    await setupNavUser();
    
    // 2. Get Current User Data
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.user) {
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('email', session.user.email)
            .single();
        currentUser = user;
        
        // Load Solved Challenges
        await loadUserProgress();
    }

    // 3. Load All Challenges from DB
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
        `);  
        
    if (!error && challenges) {
        dbChallenges = challenges;
    }

    createParticles();
    updatePointsDisplay(); // Update UI points
});

async function loadUserProgress() {
    if (!currentUser) return;
    const { data } = await supabase
        .from('submissions')
        .select('challenge_id, is_correct')
        .eq('user_id', currentUser.user_id)
        .eq('is_correct', true);
        
    if (data) {
        // เก็บ ID ของโจทย์ที่ทำได้แล้ว
        userProgressDB = data.reduce((acc, sub) => {
            acc[sub.challenge_id] = true;
            return acc;
        }, {});
    }
}

// --- 3.1 CHECK FLAG (DATABASE) ---

window.checkFlag = async function(shortId) {
    // 1. Check Login
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.user) {
        showNotification('⚠️ กรุณาเข้าสู่ระบบก่อนส่งคำตอบ', 'warning');
        return;
    }

    // 2. Get Input Value
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

    // 3. Find Challenge in DB
    const targetTitle = ID_MAPPING[shortId];
    const dbChallenge = dbChallenges.find(c => c.title === targetTitle);

    if (!dbChallenge) {
        console.error(`Challenge not found: ${targetTitle}`);
        showNotification('Error: Challenge not found', 'error');
        return;
    }

    try {
        // 4. Disable input during validation
        if (inputEl) inputEl.disabled = true;
        showNotification('🔍 กำลังตรวจสอบ...', 'info');

        // 5. ✅ Call SECURE Edge Function
        const { data, error } = await supabase.functions.invoke('validate-flag', {
            body: {
                challenge_id: dbChallenge.challenge_id,
                flag: userFlag
            }
        });

        if (error) throw error;
        if (!data.success) throw new Error(data.error || 'Validation failed');

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
        if (inputEl) inputEl.disabled = false;
    }
};

// --- 3.2 HINT SYSTEM (DATABASE) ---
// --- 3.2 HINT SYSTEM (DATABASE) ---
window.toggleHint = async function(hintId) {
    if (!currentUser) {
        showNotification('⚠️ กรุณาเข้าสู่ระบบเพื่อใช้ Hint', 'warning');
        return;
    }

    const hintEl = document.getElementById(hintId);
    if (!hintEl) {
        console.error("Hint Element Not Found:", hintId);
        return;
    }

    // ถ้า hint เปิดอยู่แล้ว → ปิด
    if (hintEl.style.display === 'block') {
        hintEl.style.display = 'none';
        return;
    }

    // Parse ID: "xsshint1" -> rawId="xss", hintNumber=1
    const matches = hintId.match(/^(.+?)hint(\d+)$/);
    if (!matches) {
        hintEl.style.display = 'block';
        return;
    }

    const rawId = matches[1];
    const hintNumber = parseInt(matches[2]);

    // แปลงชื่อย่อ (xss) เป็นชื่อจริง (xssStealer)
    const realInteractiveId = LEGACY_MAP[rawId] || rawId;

    // หา Challenge ใน DB ด้วย ID ที่แปลงแล้ว
    const dbChallenge = dbChallenges.find(c => c.interactive_id === realInteractiveId);

    if (!dbChallenge) {
        console.warn(`Challenge not found in DB for interactive_id: ${realInteractiveId} (raw: ${rawId})`);
        // ถ้าไม่เจอใน DB ให้เปิด hint เลย (challenge ที่ไม่มีใน DB)
        hintEl.style.display = 'block';
        return;
    }

    try {
        // ✅ เช็คว่า user เคยใช้ hint นี้หรือยัง
        const { data: hintData } = await supabase
            .from('hints')
            .select('hint_id')
            .eq('challenge_id', dbChallenge.challenge_id)
            .eq('order_index', hintNumber)
            .single();

        if (hintData) {
            // เช็คว่าเคยใช้ hint นี้แล้วหรือยัง
            const { data: usedHint, error: checkError } = await supabase
                .from('user_hints')
                .select('*')
                .eq('user_id', currentUser.user_id)
                .eq('challenge_id', dbChallenge.challenge_id)
                .eq('hint_id', hintData.hint_id)
                .maybeSingle();

            if (!checkError && usedHint) {
                // ✅ เคยใช้แล้ว → เปิด hint เลย ไม่ต้องเตือน
                hintEl.style.display = 'block';
                console.log(`Hint already used: ${hintId}`);
                return;
            }
        }

        // ❗ ยังไม่เคยใช้ → แสดง confirmation
        showHintConfirmation(hintId, HINT_PENALTY, async () => {
            // 1. เปิด Hint (UI Feedback)
            hintEl.style.display = 'block';

            // 2. บันทึกการใช้ Hint ลง Database
            if (hintData) {
                const { error: insertError } = await supabase
                    .from('user_hints')
                    .insert({
                        user_id: currentUser.user_id,
                        challenge_id: dbChallenge.challenge_id,
                        hint_id: hintData.hint_id,
                        used_at: new Date().toISOString()
                    });
                
                if (insertError && insertError.code !== '23505') {
                    console.warn("Hint DB log error:", insertError.message);
                } else {
                    console.log(`✅ Hint logged: ${hintId}`);
                }
            }
        });

    } catch (err) {
        console.error("Hint Logic Error:", err);
        // ถ้า error ให้เปิด hint เลย
        hintEl.style.display = 'block';
    }
};


// --- 3.3 MODAL OPENER ---
window.openInteractiveChallenge = function(shortId) {
    // หา HTML Content
    const content = interactiveChallenges[shortId]?.content;
    
    if (!content) {
        alert('Error: Challenge content not found for ' + shortId);
        return;
    }

    // Inject HTML
    const container = document.getElementById('interactiveContent');
    container.innerHTML = content;

    // Show Modal
    document.getElementById('interactiveModal').classList.add('active');
    
    // Update Score Display in Modal (if element exists)
    if (currentUser) {
        const pointsEl = container.querySelector('.current-points');
        if (pointsEl) pointsEl.textContent = currentUser.score;
    }
};

// ============================================
// 4. HTML CONTENT TEMPLATES (The Massive Object)
// ============================================
// เก็บ HTML เดิมไว้ เพื่อให้ UI ไม่พัง
const interactiveChallenges = {
    sqlInjection: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🌐 SQL Injection Login Bypass</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>คุณได้รับมอบหมายให้ทำ Penetration Testing บนระบบ SecureBank Authentication ซึ่งมีช่องโหว่ SQL Injection ที่ถูกซ่อนไว้</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • Target: SecureBank Authentication Portal v3.2<br>
                    • Backend Database: MySQL 8.0<br>
                    • มี WAF filter บาง keywords แต่เป็น case-sensitive<br>
                    • Goal: Bypass authentication เพื่อเข้าถึง admin account
                </div>

                <div style="background: rgba(0,212,255,0.1); border-left: 3px solid var(--secondary); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>🔍 Intelligence Report:</strong><br>
                    • Query Pattern: <code>SELECT * FROM users WHERE username='$input' AND password='$input'</code><br>
                    • Admin username: <code>admin</code><br>
                    • Filter เป็น case-sensitive (OR ถูก block แต่ Or, oR ไม่ถูก block)
                </div>
            </div>

            <div class="sql-interface">
                <div class="login-panel">
                    <div class="panel-header">
                        <div class="status-indicator"></div>
                        <span>SecureBank Authentication System v3.2</span>
                    </div>
                    
                    <div class="login-form">
                        <div class="form-group">
                            <label>👤 Username</label>
                            <input type="text" id="sqlUser" placeholder="Enter username" 
                                style="background: rgba(0,0,0,0.6); border: 2px solid var(--primary); 
                                color: var(--light); padding: 0.8rem; width: 100%; border-radius: 8px;
                                font-family: 'Courier New', monospace;">
                        </div>
                        
                        <div class="form-group">
                            <label>🔒 Password</label>
                            <input type="password" id="sqlPass" placeholder="Enter password"
                                style="background: rgba(0,0,0,0.6); border: 2px solid var(--primary); 
                                color: var(--light); padding: 0.8rem; width: 100%; border-radius: 8px;
                                font-family: 'Courier New', monospace;">
                        </div>
                        
                        <button onclick="attemptSQLLogin()" class="login-btn">
                            <span>🔐 LOGIN</span>
                        </button>
                    </div>
                    
                    <div id="sqlResult" class="result-panel"></div>
                </div>

                <div class="debug-panel">
                    <div class="debug-header">🔍 Query Debug Panel</div>
                    <div id="sqlDebug" class="debug-content">
                        <p style="color: var(--gray);">[ Waiting for login attempt... ]</p>
                    </div>
                </div>

                <div class="filter-panel">
                    <div class="filter-header">🛡️ WAF Security Rules</div>
                    <div class="filter-content">
                        <div class="filter-item">❌ Blocked: <code>OR</code> (exact uppercase)</div>
                        <div class="filter-item">❌ Blocked: <code>AND</code> (exact uppercase)</div>
                        <div class="filter-item">❌ Blocked: <code>--</code> (double dash)</div>
                        <div class="filter-item">❌ Blocked: <code>/*</code> (C-style comment)</div>
                        <div class="filter-item">✅ Allowed: <code>#</code>, single quotes</div>
                        <div class="filter-item" style="color: var(--warning);">⚠️ Filter is case-sensitive!</div>
                    </div>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('sqlhint1')">💡 Hint 1: Filter Analysis (-10 pts)</button>
                <div id="sqlhint1" class="hint-content" style="display:none;">
                    <strong>🔓 Filter Bypass Concept:</strong><br>
                    WAF ตรวจจับ keywords แบบ exact match และ case-sensitive<br><br>
                    • "OR" ถูก block แต่ "Or", "oR", "or" ผ่านได้<br>
                    • MySQL ไม่สนใจ case ของ SQL keywords<br>
                    • ลองใช้ mixed case: <code>oR</code>, <code>Or</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('sqlhint2')">💡 Hint 2: Query Structure (-10 pts)</button>
                <div id="sqlhint2" class="hint-content" style="display:none;">
                    <strong>📝 SQL Query Analysis:</strong><br>
                    Original: <code>SELECT * FROM users WHERE username='[INPUT]' AND password='[INPUT]'</code><br><br>
                    เป้าหมาย: ทำให้ WHERE clause return TRUE<br>
                    • ใช้ <code>' oR '1'='1</code> สร้าง always-true condition<br>
                    • ใช้ <code>#</code> comment out ส่วน password check
                </div>

                <button class="hint-btn" onclick="toggleHint('sqlhint3')">💡 Hint 3: Working Payload (-10 pts)</button>
                <div id="sqlhint3" class="hint-content" style="display:none;">
                    <strong>✅ Payloads ที่ใช้ได้:</strong><br>
                    • Username: <code>admin' oR '1'='1' #</code><br>
                    • Username: <code>admin' Or 1=1 #</code><br>
                    • Username: <code>' oR 1=1 #</code> (login as first user)<br>
                    • Password: ใส่อะไรก็ได้ (ถูก comment out)
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="sqlInjectionFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('sqlInjection')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="sqlSuccess"></div>
            <div class="error-message" id="sqlError"></div>
        `
    },
    //Web 2
    cmdInjection: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🌐 Command Injection Shell</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>คุณค้นพบ Network Diagnostic Tool ที่มีช่องโหว่ Command Injection สามารถ execute OS commands ผ่าน web interface ได้</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • Target: Corporate Network Diagnostic Portal<br>
                    • OS: Linux Ubuntu 22.04 LTS<br>
                    • Vulnerable function: ping utility<br>
                    • Goal: ค้นหาและอ่านไฟล์ flag.txt ที่ซ่อนอยู่ใน /var/www/app/secret/
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">user@diagnostic-server:~ — bash</span>
                </div>
                <div id="cmdTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           NETWORK DIAGNOSTIC TOOL v2.1                       │
    │           Authorized Personnel Only                          │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">System Information:</span>
    <span style="color: #7ee787;">  OS:</span> Ubuntu 22.04.3 LTS
    <span style="color: #7ee787;">  Kernel:</span> 5.15.0-91-generic
    <span style="color: #7ee787;">  User:</span> www-data

    <span style="color: #8b949e;">Enter target IP/hostname to ping. Type 'help' for commands.</span>
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    </div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="cmdInput" placeholder="ping 127.0.0.1" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeCMD();">
                    <button onclick="executeCMD()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('cmdhint1')">💡 Hint 1: Command Chaining (-10 pts)</button>
                <div id="cmdhint1" class="hint-content" style="display:none;">
                    <strong>🔗 Command Injection Basics:</strong><br>
                    Linux allows chaining commands:<br>
                    • <code>;</code> - Execute sequentially<br>
                    • <code>&&</code> - Execute if previous succeeds<br>
                    • <code>||</code> - Execute if previous fails<br>
                    • <code>|</code> - Pipe output<br>
                    • <code>\`cmd\`</code> or <code>$(cmd)</code> - Command substitution<br><br>
                    Example: <code>127.0.0.1; whoami</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('cmdhint2')">💡 Hint 2: File Discovery (-10 pts)</button>
                <div id="cmdhint2" class="hint-content" style="display:none;">
                    <strong>🔍 Useful Commands:</strong><br>
                    • <code>ls -la</code> - List all files<br>
                    • <code>find / -name "flag*" 2>/dev/null</code> - Search files<br>
                    • <code>cat /etc/passwd</code> - View users<br>
                    • <code>pwd</code> - Current directory<br><br>
                    Try: <code>; ls -la /var/www/</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('cmdhint3')">💡 Hint 3: Flag Location (-10 pts)</button>
                <div id="cmdhint3" class="hint-content" style="display:none;">
                    <strong>📁 Flag Location:</strong><br>
                    Flag อยู่ที่: <code>/var/www/app/secret/flag.txt</code><br><br>
                    Commands:<br>
                    • <code>; ls /var/www/app/secret/</code><br>
                    • <code>; cat /var/www/app/secret/flag.txt</code>
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="sqlInjectionFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('cmdInjection')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="cmdSuccess"></div>
            <div class="error-message" id="cmdError"></div>
        `
    },
    //Web 3
    xssStealer: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🌐 XSS Cookie Stealer</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>คุณค้นพบระบบ Comment ที่มีช่องโหว่ Stored XSS แม้จะมี filter บาง tags แต่ยังสามารถ bypass ได้</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • Target: Corporate Blog Comment System<br>
                    • Vulnerability: Stored XSS<br>
                    • Admin เข้ามาดู comments ทุก 30 วินาที<br>
                    • Goal: ขโมย admin session cookie
                </div>

                <div style="background: rgba(255,0,0,0.1); border-left: 3px solid var(--danger); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>🛡️ XSS Filter:</strong><br>
                    • ❌ Blocked: <code>&lt;script&gt;</code> tag<br>
                    • ❌ Blocked: <code>onerror</code> attribute<br>
                    • ❌ Blocked: <code>onclick</code> attribute<br>
                    • ✅ Allowed: Other HTML tags & event handlers
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d;">
                    <span style="color: #c9d1d9;">💬 Corporate Blog - Comment Section</span>
                </div>
                <div style="padding: 1.5rem;">
                    <div style="margin-bottom: 1rem;">
                        <label style="color: #8b949e; display: block; margin-bottom: 0.5rem;">Your Name:</label>
                        <input type="text" id="xssName" value="Anonymous" style="width: 100%; padding: 0.7rem; background: #21262d; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-family: inherit;">
                    </div>
                    <div style="margin-bottom: 1rem;">
                        <label style="color: #8b949e; display: block; margin-bottom: 0.5rem;">Comment:</label>
                        <textarea id="xssInput" rows="4" style="width: 100%; padding: 0.7rem; background: #21262d; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-family: 'Courier New', monospace; resize: vertical;" placeholder="Write your comment..."></textarea>
                    </div>
                    <button onclick="submitXSS()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.8rem 2rem; border-radius: 6px; cursor: pointer; font-weight: bold;">📤 Post Comment</button>
                    
                    <div id="xssFilterLog" style="margin-top: 1rem; font-family: monospace; font-size: 0.85rem;"></div>
                </div>
                
                <div style="border-top: 1px solid #30363d; padding: 1.5rem;">
                    <h4 style="color: #58a6ff; margin-bottom: 1rem;">📝 Posted Comments:</h4>
                    <div id="xssComments" style="max-height: 200px; overflow-y: auto;"></div>
                </div>
                
                <div id="xssResult" style="padding: 0 1.5rem 1.5rem;"></div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('xsshint1')">💡 Hint 1: Filter Bypass (-10 pts)</button>
                <div id="xsshint1" class="hint-content" style="display:none;">
                    <strong>🔓 Alternative XSS Vectors:</strong><br>
                    &lt;script&gt; ถูก block แต่ยังมี tags อื่น:<br>
                    • <code>&lt;svg onload=...&gt;</code><br>
                    • <code>&lt;img src=x oNLoAd=...&gt;</code> (mixed case)<br>
                    • <code>&lt;body onpageshow=...&gt;</code><br>
                    • <code>&lt;input onfocus=... autofocus&gt;</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('xsshint2')">💡 Hint 2: Event Handlers (-10 pts)</button>
                <div id="xsshint2" class="hint-content" style="display:none;">
                    <strong>⚡ Working Event Handlers:</strong><br>
                    • <code>onload</code> - element loads<br>
                    • <code>onmouseover</code> - mouse hover<br>
                    • <code>onfocus</code> - element focused<br>
                    • <code>onanimationend</code> - CSS animation<br><br>
                    Example: <code>&lt;svg/onload=alert(1)&gt;</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('xsshint3')">💡 Hint 3: Cookie Access (-10 pts)</button>
                <div id="xsshint3" class="hint-content" style="display:none;">
                    <strong>🍪 Cookie Extraction:</strong><br>
                    ใช้ <code>document.cookie</code> เข้าถึง cookies<br><br>
                    Payload:<br>
                    <code>&lt;svg/onload=alert(document.cookie)&gt;</code><br>
                    <code>&lt;img src=x oNLoAd=alert(document.cookie)&gt;</code>
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="sqlInjectionFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('xssStealer')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="xssSuccess"></div>
            <div class="error-message" id="xssError"></div>
        `
    },
    //Crypto 1
    multiCipher: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🔐 CyberChef Decoder</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>คุณได้รับข้อความเข้ารหัสที่ใช้หลาย encoding layers ซ้อนกัน ใช้ CyberChef วิเคราะห์และถอดรหัสเพื่อหา flag</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • ข้อความถูกเข้ารหัสหลายชั้น<br>
                    • ต้องวิเคราะห์ว่าใช้ encoding อะไรบ้าง<br>
                    • ลาก operations ไปใส่ Recipe เพื่อถอดรหัส<br>
                    • เรียงลำดับ operations ให้ถูกต้อง
                </div>
            </div>

            <!-- CyberChef Interface -->
            <div class="cyberchef-container">
                <!-- Operations Panel -->
                <div class="cyberchef-operations">
                    <div class="operations-header">
                        <span>🧰 Operations</span>
                        <input type="text" id="opSearch" placeholder="Search..." 
                            style="width: 100%; margin-top: 0.5rem; padding: 0.5rem; background: rgba(0,0,0,0.5); border: 1px solid var(--gray); border-radius: 4px; color: var(--light); font-size: 0.85rem;"
                            oninput="filterOperations(this.value)">
                    </div>
                    <div class="operations-list" id="operationsList">
                        <div class="op-category">
                            <div class="op-category-header">📝 Data Format</div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="base64decode">
                                <span class="op-icon">🔓</span> From Base64
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="base64encode">
                                <span class="op-icon">🔒</span> To Base64
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="hexdecode">
                                <span class="op-icon">🔓</span> From Hex
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="hexencode">
                                <span class="op-icon">🔒</span> To Hex
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="urldecode">
                                <span class="op-icon">🔓</span> URL Decode
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="urlencode">
                                <span class="op-icon">🔒</span> URL Encode
                            </div>
                        </div>
                        <div class="op-category">
                            <div class="op-category-header">🔄 Encryption / Encoding</div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="rot13">
                                <span class="op-icon">🔄</span> ROT13
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="rot47">
                                <span class="op-icon">🔄</span> ROT47
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="reverse">
                                <span class="op-icon">↩️</span> Reverse
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="xor">
                                <span class="op-icon">⊕</span> XOR
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="atbash">
                                <span class="op-icon">🔤</span> Atbash Cipher
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="caesar">
                                <span class="op-icon">🏛️</span> Caesar Cipher
                            </div>
                        </div>
                        <div class="op-category">
                            <div class="op-category-header">🔧 Utils</div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="lowercase">
                                <span class="op-icon">⬇️</span> To Lowercase
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="uppercase">
                                <span class="op-icon">⬆️</span> To Uppercase
                            </div>
                            <div class="op-item" draggable="true" ondragstart="dragOp(event)" data-op="removewhitespace">
                                <span class="op-icon">✂️</span> Remove Whitespace
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recipe Panel -->
                <div class="cyberchef-recipe">
                    <div class="recipe-header">
                        <span>📜 Recipe</span>
                        <button onclick="clearRecipe()" class="recipe-clear-btn">🗑️ Clear</button>
                    </div>
                    <div class="recipe-drop-zone" id="recipeZone" 
                        ondrop="dropOp(event)" ondragover="allowDrop(event)">
                        <div class="recipe-placeholder" id="recipePlaceholder">
                            ⬇️ Drag operations here
                        </div>
                        <div id="recipeList"></div>
                    </div>
                    <button onclick="bakeRecipe()" class="bake-btn">
                        🔥 BAKE!
                    </button>
                </div>

                <!-- Input/Output Panel -->
                <div class="cyberchef-io">
                    <div class="io-section">
                        <div class="io-header">
                            <span>📥 Input</span>
                            <button onclick="loadChallenge()" class="io-btn">📋 Load Challenge</button>
                        </div>
                        <textarea id="chefInput" class="io-textarea" placeholder="Enter data to decode..."></textarea>
                    </div>
                    <div class="io-section">
                        <div class="io-header">
                            <span>📤 Output</span>
                            <button onclick="copyOutput()" class="io-btn">📋 Copy</button>
                        </div>
                        <textarea id="chefOutput" class="io-textarea" readonly placeholder="Output will appear here..."></textarea>
                    </div>
                </div>
            </div>

            <!-- Challenge Data -->
            <div class="cipher-box" style="margin-top: 1.5rem;">
                <h4 style="color: var(--purple); margin-bottom: 1rem;">🔒 Encrypted Message:</h4>
                <div style="background: rgba(0,0,0,0.5); padding: 1rem; border-radius: 8px; font-family: 'Courier New', monospace; word-break: break-all; font-size: 0.9rem; color: var(--warning);" id="challengeData">
                    4a5449314e6b786c596e4a7a5a5664665a6d78685a31397a5a574e59634778766369686c
                </div>
                <p style="color: var(--gray); margin-top: 0.5rem; font-size: 0.85rem;">
                    💡 Hint: สังเกต pattern ของข้อมูล - ตัวเลขและตัวอักษร a-f บ่งบอกว่าเป็น encoding แบบไหน?
                </p>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('chefhint1')">💡 Hint 1: Identify Encoding (-10 pts)</button>
                <div id="chefhint1" class="hint-content" style="display:none;">
                    <strong>🔍 Pattern Analysis:</strong><br>
                    • ตัวเลข 0-9 และ a-f เท่านั้น = <strong>Hexadecimal</strong><br>
                    • ลงท้ายด้วย = หรือ == = <strong>Base64</strong><br>
                    • ตัวอักษรแปลกๆ = อาจเป็น ROT13 หรือ Caesar<br><br>
                    ข้อมูลนี้เป็น Hex → ลอง "From Hex" ก่อน
                </div>

                <button class="hint-btn" onclick="toggleHint('chefhint2')">💡 Hint 2: Layer Order (-10 pts)</button>
                <div id="chefhint2" class="hint-content" style="display:none;">
                    <strong>📋 Encoding Layers:</strong><br>
                    ข้อมูลถูก encode ตามลำดับ:<br>
                    1. Plaintext → Base64<br>
                    2. Base64 → ROT13<br>
                    3. ROT13 → Hex<br><br>
                    ถอดรหัสย้อนกลับ: Hex → ROT13 → Base64
                </div>

                <button class="hint-btn" onclick="toggleHint('chefhint3')">💡 Hint 3: Recipe (-10 pts)</button>
                <div id="chefhint3" class="hint-content" style="display:none;">
                    <strong>✅ Recipe ที่ถูกต้อง:</strong><br>
                    1. From Hex<br>
                    2. ROT13<br>
                    3. From Base64<br><br>
                    ลาก operations เหล่านี้ไปใส่ Recipe แล้วกด BAKE!
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="multiCipherFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('multiCipher')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="multiSuccess"></div>
            <div class="error-message" id="multiError"></div>
        `
    },
    //Crypto 2
    xorBrute: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🔐 XOR Brute Force</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>ข้อความถูกเข้ารหัสด้วย Single-byte XOR cipher ต้องใช้ brute force หา key ที่ถูกต้อง</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • Cipher: Single-byte XOR<br>
                    • Key space: 0x00 - 0xFF (256 possibilities)<br>
                    • Known: Flag format เริ่มด้วย "secXplore{"<br>
                    • Goal: หา key และถอดรหัสข้อความ
                </div>
            </div>

            <div class="cipher-box" style="background: rgba(156,136,255,0.1); border: 2px solid var(--purple); border-radius: 10px; padding: 1.5rem; margin: 1.5rem 0;">
                <h4 style="color: var(--purple); margin-bottom: 1rem;">🔒 Encrypted Data (Hex):</h4>
                <div style="background: rgba(0,0,0,0.5); padding: 1rem; border-radius: 8px; font-family: 'Courier New', monospace; word-break: break-all; font-size: 0.85rem; color: var(--warning);">
                    12 2c 20 67 17 2f 29 1b 2c 4a 37 2b 1b 78 31 1e 2d 0e 78 31 29 2e 12 2c 4c
                </div>
            </div>

            <div class="tool-section" style="background: rgba(0,0,0,0.3); border: 1px solid var(--secondary); border-radius: 10px; padding: 1.5rem; margin: 1.5rem 0;">
                <h4 style="color: var(--secondary); margin-bottom: 1rem;">🛠️ XOR Cracker Tool</h4>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                    <div>
                        <label style="color: var(--gray); display: block; margin-bottom: 0.5rem;">Key (0-255 or 0x00-0xFF):</label>
                        <input type="text" id="xorKey" value="0x41" style="width: 100%; padding: 0.7rem; background: rgba(0,0,0,0.5); border: 1px solid var(--secondary); border-radius: 5px; color: var(--light); font-family: monospace;">
                    </div>
                    <div>
                        <label style="color: var(--gray); display: block; margin-bottom: 0.5rem;">Hex Input:</label>
                        <input type="text" id="xorInput" value="12 2c 20 67 17 2f 29 1b 2c 4a 37 2b 1b 78 31 1e 2d 0e 78 31 29 2e 12 2c 4c" style="width: 100%; padding: 0.7rem; background: rgba(0,0,0,0.5); border: 1px solid var(--secondary); border-radius: 5px; color: var(--light); font-family: monospace; font-size: 0.8rem;">
                    </div>
                </div>
                
                <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
                    <button onclick="xorDecrypt()" style="flex: 1; background: var(--secondary); color: var(--dark); border: none; padding: 0.8rem; border-radius: 5px; cursor: pointer; font-weight: bold;">🔓 Decrypt</button>
                    <button onclick="xorBruteForce()" style="flex: 1; background: var(--purple); color: white; border: none; padding: 0.8rem; border-radius: 5px; cursor: pointer; font-weight: bold;">🔨 Brute Force</button>
                </div>
                
                <div id="xorOutput" style="background: rgba(0,0,0,0.5); padding: 1rem; border-radius: 8px; min-height: 100px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 0.85rem;"></div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('xorhint1')">💡 Hint 1: XOR Properties (-10 pts)</button>
                <div id="xorhint1" class="hint-content" style="display:none;">
                    <strong>⚡ XOR Properties:</strong><br>
                    • A XOR B = C<br>
                    • C XOR B = A (reversible)<br>
                    • A XOR A = 0<br><br>
                    ถ้ารู้ plaintext บางส่วน สามารถหา key ได้:<br>
                    plaintext[0] XOR ciphertext[0] = key
                </div>

                <button class="hint-btn" onclick="toggleHint('xorhint2')">💡 Hint 2: Known Plaintext (-10 pts)</button>
                <div id="xorhint2" class="hint-content" style="display:none;">
                    <strong>🔍 Known Plaintext Attack:</strong><br>
                    Flag format: "secXplore{"<br>
                    First char: 's' = 0x73<br>
                    First cipher byte: 0x12<br><br>
                    Key = 0x12 XOR 0x73 = ?<br>
                    ลองคำนวณดู!
                </div>

                <button class="hint-btn" onclick="toggleHint('xorhint3')">💡 Hint 3: Key Value (-10 pts)</button>
                <div id="xorhint3" class="hint-content" style="display:none;">
                    <strong>🔑 Key Calculation:</strong><br>
                    0x12 XOR 0x73 = 0x61 (97 decimal)<br>
                    Key = 0x61 = 'a' in ASCII<br><br>
                    ลองใช้ key = 97 หรือ 0x61
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="xorKnownFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('xorBrute')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="xorSuccess"></div>
            <div class="error-message" id="xorError"></div>
        `
    },
    //Crypto 3
    rsaAttack: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🔐 RSA Small Exponent Attack</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>พบระบบ RSA ที่ใช้ public exponent e=3 และส่งข้อความเดียวกันไปยัง 3 recipients ที่มี modulus ต่างกัน</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • RSA public exponent: e = 3<br>
                    • Same message sent to 3 different recipients<br>
                    • Different modulus (n1, n2, n3)<br>
                    • Vulnerability: Håstad's Broadcast Attack<br>
                    • Goal: Recover plaintext using Chinese Remainder Theorem
                </div>
            </div>

            <div class="cipher-box" style="background: rgba(156,136,255,0.1); border: 2px solid var(--purple); border-radius: 10px; padding: 1.5rem; margin: 1.5rem 0;">
                <h4 style="color: var(--purple); margin-bottom: 1rem;">🔢 RSA Parameters:</h4>
                <div style="background: rgba(0,0,0,0.5); padding: 1rem; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 0.85rem;">
                    <div style="color: var(--success); margin-bottom: 1rem;">e = 3</div>
                    
                    <div style="color: var(--secondary); margin-bottom: 0.5rem;">Recipient 1:</div>
                    <div style="color: var(--light); margin-left: 1rem; margin-bottom: 0.5rem;">n1 = 95642412847883940786305809307353693569</div>
                    <div style="color: var(--warning); margin-left: 1rem; margin-bottom: 1rem;">c1 = 43521958879546920674859726231851901</div>
                    
                    <div style="color: var(--secondary); margin-bottom: 0.5rem;">Recipient 2:</div>
                    <div style="color: var(--light); margin-left: 1rem; margin-bottom: 0.5rem;">n2 = 117459929787100018763388685239228564389</div>
                    <div style="color: var(--warning); margin-left: 1rem; margin-bottom: 1rem;">c2 = 82758039917642834312341917436251951</div>
                    
                    <div style="color: var(--secondary); margin-bottom: 0.5rem;">Recipient 3:</div>
                    <div style="color: var(--light); margin-left: 1rem; margin-bottom: 0.5rem;">n3 = 122656808337815211204693407655668838229</div>
                    <div style="color: var(--warning); margin-left: 1rem;">c3 = 91274127489237491827412983749127489</div>
                </div>
            </div>

            <div class="tool-section" style="background: rgba(0,0,0,0.3); border: 1px solid var(--secondary); border-radius: 10px; padding: 1.5rem; margin: 1.5rem 0;">
                <h4 style="color: var(--secondary); margin-bottom: 1rem;">🛠️ RSA Attack Tools</h4>
                
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; margin-bottom: 1rem;">
                    <button onclick="rsaShowCRT()" class="tool-btn">📐 CRT Formula</button>
                    <button onclick="rsaCalculateCRT()" class="tool-btn">🔢 Calculate m³</button>
                    <button onclick="rsaCubeRoot()" class="tool-btn">∛ Cube Root</button>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; margin-bottom: 1rem;">
                    <button onclick="rsaToBytes()" class="tool-btn">📝 To ASCII</button>
                    <button onclick="rsaSolveAll()" style="background: var(--success); color: var(--dark); border: none; padding: 0.8rem; border-radius: 5px; cursor: pointer; font-weight: bold;">🚀 Solve All</button>
                </div>
                
                <div id="rsaOutput" style="background: rgba(0,0,0,0.5); padding: 1rem; border-radius: 8px; min-height: 150px; max-height: 350px; overflow-y: auto; font-family: monospace; font-size: 0.85rem;"></div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('rsahint1')">💡 Hint 1: Håstad's Attack (-10 pts)</button>
                <div id="rsahint1" class="hint-content" style="display:none;">
                    <strong>🎯 Håstad's Broadcast Attack:</strong><br>
                    เมื่อ e=3 และส่งข้อความเดียวกัน m ไป 3 คน:<br>
                    • c1 ≡ m³ (mod n1)<br>
                    • c2 ≡ m³ (mod n2)<br>
                    • c3 ≡ m³ (mod n3)<br><br>
                    ใช้ CRT หา m³ mod (n1*n2*n3)<br>
                    ถ้า m³ < n1*n2*n3 → หา cube root ได้โดยตรง
                </div>

                <button class="hint-btn" onclick="toggleHint('rsahint2')">💡 Hint 2: Chinese Remainder Theorem (-10 pts)</button>
                <div id="rsahint2" class="hint-content" style="display:none;">
                    <strong>📐 CRT Formula:</strong><br>
                    N = n1 × n2 × n3<br>
                    N1 = N/n1, N2 = N/n2, N3 = N/n3<br><br>
                    หา y1, y2, y3 ที่:<br>
                    • N1 × y1 ≡ 1 (mod n1)<br>
                    • N2 × y2 ≡ 1 (mod n2)<br>
                    • N3 × y3 ≡ 1 (mod n3)<br><br>
                    m³ = (c1×N1×y1 + c2×N2×y2 + c3×N3×y3) mod N
                </div>

                <button class="hint-btn" onclick="toggleHint('rsahint3')">💡 Hint 3: Solution Steps (-10 pts)</button>
                <div id="rsahint3" class="hint-content" style="display:none;">
                    <strong>✅ Steps:</strong><br>
                    1. ใช้ CRT หา m³<br>
                    2. คำนวณ ∛m³ = m<br>
                    3. แปลง m เป็น bytes<br>
                    4. Decode เป็น ASCII text<br><br>
                    กดปุ่ม "Solve All" เพื่อดู solution
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="xorKnownFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('rsaAttack')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="rsaSuccess"></div>
            <div class="error-message" id="rsaError"></div>
        `
    },
    //Forensic 1
    birthdayExif: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🔍 Hidden Birthday Message</h2>
            <img src="1_Hbd_20th.png" class="challenge-header-img" alt="Birthday Exif">
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>คุณได้รับไฟล์รูปภาพที่มีข้อมูล EXIF metadata ซ่อนอยู่ ต้องวิเคราะห์ metadata เพื่อหา flag</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • File: birthday_photo.jpg<br>
                    • มีข้อมูลสำคัญซ่อนใน EXIF metadata<br>
                    • ต้องใช้ exiftool วิเคราะห์ข้อมูล<br>
                    • Flag ซ่อนอยู่ใน Comment หรือ User Comment field
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">forensics@workstation:~/evidence — bash</span>
                </div>
                <div id="birthdayTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           EXIF METADATA ANALYZER                             │
    │           Digital Forensics Workstation                      │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Evidence file loaded: birthday_photo.jpg (2.4 MB)</span>
    <span style="color: #7ee787;">Available commands:</span> exiftool, file, strings, xxd, hexdump, binwalk
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="birthdayCommand" placeholder="exiftool birthday_photo.jpg" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeBirthdayCommand();">
                    <button onclick="executeBirthdayCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('birthdayhint1')">💡 Hint 1: EXIF Basics (-10 pts)</button>
                <div id="birthdayhint1" class="hint-content" style="display:none;">
                    <strong>📷 EXIF Metadata:</strong><br>
                    EXIF เก็บข้อมูลเกี่ยวกับรูปภาพ:<br>
                    • Camera model, settings<br>
                    • Date/Time taken<br>
                    • GPS coordinates<br>
                    • Comments & descriptions<br><br>
                    ใช้: <code>exiftool birthday_photo.jpg</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('birthdayhint2')">💡 Hint 2: Specific Fields (-10 pts)</button>
                <div id="birthdayhint2" class="hint-content" style="display:none;">
                    <strong>🔍 Look for:</strong><br>
                    • Comment field<br>
                    • User Comment field<br>
                    • Image Description<br>
                    • Artist or Copyright<br><br>
                    ใช้: <code>exiftool -Comment birthday_photo.jpg</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('birthdayhint3')">💡 Hint 3: Extract All (-10 pts)</button>
                <div id="birthdayhint3" class="hint-content" style="display:none;">
                    <strong>📋 Commands:</strong><br>
                    • <code>exiftool -a -u birthday_photo.jpg</code> (all tags)<br>
                    • <code>exiftool -Comment -UserComment birthday_photo.jpg</code><br>
                    • Flag จะอยู่ใน User Comment field
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="birthdayExifFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('birthdayExif')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="birthdaySuccess"></div>
            <div class="error-message" id="birthdayError"></div>
        `
    },
    //Forensic 2
    geoLocation: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🔍 Geolocation Mystery</h2>
            <img src="2_Where_is_it.jpg" class="challenge-header-img" alt="Geolocation">
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>ไฟล์รูปภาพมี GPS coordinates ซ่อนอยู่ ต้องหาพิกัดและระบุตำแหน่งเพื่อหา flag</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • File: mystery_location.jpg<br>
                    • มี GPS metadata ที่บอกตำแหน่งถ่ายภาพ<br>
                    • ต้องหาชื่อสถานที่และสร้าง flag<br>
                    • Flag format: secXplore{location_name_lowercase_no_spaces}
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">forensics@workstation:~/evidence — bash</span>
                </div>
                <div id="geoTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           GEOLOCATION FORENSICS TOOL                         │
    │           GPS Coordinate Extractor                           │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Evidence file loaded: mystery_location.jpg (1.8 MB)</span>
    <span style="color: #7ee787;">Available commands:</span> exiftool, file, identify, strings
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="geoCommand" placeholder="exiftool -GPS* mystery_location.jpg" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeGeoCommand();">
                    <button onclick="executeGeoCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('geohint1')">💡 Hint 1: GPS Extraction (-10 pts)</button>
                <div id="geohint1" class="hint-content" style="display:none;">
                    <strong>📍 GPS Commands:</strong><br>
                    • <code>exiftool -GPS* mystery_location.jpg</code><br>
                    • <code>exiftool -n -GPS* mystery_location.jpg</code> (decimal)<br>
                    • <code>exiftool -c "%.6f" mystery_location.jpg</code><br><br>
                    จะได้ Latitude และ Longitude
                </div>

                <button class="hint-btn" onclick="toggleHint('geohint2')">💡 Hint 2: Coordinate Format (-10 pts)</button>
                <div id="geohint2" class="hint-content" style="display:none;">
                    <strong>🌐 Coordinate Types:</strong><br>
                    • DMS: 48° 51' 24.00" N, 2° 17' 40.00" E<br>
                    • Decimal: 48.856667, 2.294444<br><br>
                    ใช้ Google Maps หรือ reverse geocoding<br>
                    URL: maps.google.com/?q=LAT,LONG
                </div>

                <button class="hint-btn" onclick="toggleHint('geohint3')">💡 Hint 3: Location (-10 pts)</button>
                <div id="geohint3" class="hint-content" style="display:none;">
                    <strong>🗼 The Location:</strong><br>
                    พิกัดจะชี้ไปที่ landmark ที่มีชื่อเสียงในปารีส<br>
                    Flag format: secXplore{landmark_name}<br>
                    (lowercase, underscore แทน space)
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="geoLocationFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('geoLocation')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="geoSuccess"></div>
            <div class="error-message" id="geoError"></div>
        `
    },
    //Forensic 3
    stegoFlag: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">🔍 Steganography Battlefield</h2>
            <img src="3_flag_img.png" class="challenge-header-img" alt="Steganography">
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>ไฟล์รูปภาพมีข้อมูลซ่อนอยู่ภายในโดยใช้ steganography technique ต้องใช้เครื่องมือวิเคราะห์หาข้อมูลที่ซ่อนไว้</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • File: innocent_image.png<br>
                    • มี hidden data ซ่อนอยู่ภายในไฟล์<br>
                    • อาจมี embedded file หรือ hidden text<br>
                    • ใช้ binwalk, steghide, strings, zsteg วิเคราะห์
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">forensics@workstation:~/evidence — bash</span>
                </div>
                <div id="stegoTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           STEGANOGRAPHY ANALYSIS SUITE                       │
    │           Hidden Data Extraction Tool                        │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Evidence file loaded: innocent_image.png (856 KB)</span>
    <span style="color: #7ee787;">Available commands:</span>
    binwalk, strings, xxd, hexdump, file, zsteg, steghide
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="stegoCommand" placeholder="binwalk innocent_image.png" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeStegoCommand();">
                    <button onclick="executeStegoCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('stegohint1')">💡 Hint 1: File Analysis (-10 pts)</button>
                <div id="stegohint1" class="hint-content" style="display:none;">
                    <strong>🔍 Analysis Commands:</strong><br>
                    • <code>file innocent_image.png</code> - file type<br>
                    • <code>binwalk innocent_image.png</code> - embedded files<br>
                    • <code>strings innocent_image.png | grep -i flag</code><br>
                    • <code>xxd innocent_image.png | head</code> - hex view
                </div>

                <button class="hint-btn" onclick="toggleHint('stegohint2')">💡 Hint 2: Extraction (-10 pts)</button>
                <div id="stegohint2" class="hint-content" style="display:none;">
                    <strong>📦 Extract Hidden Data:</strong><br>
                    • <code>binwalk -e innocent_image.png</code> - extract<br>
                    • <code>zsteg innocent_image.png</code> - LSB analysis<br>
                    • <code>steghide extract -sf file.jpg</code><br><br>
                    อาจมี ZIP file ซ่อนอยู่ภายใน
                </div>

                <button class="hint-btn" onclick="toggleHint('stegohint3')">💡 Hint 3: ZIP Password (-10 pts)</button>
                <div id="stegohint3" class="hint-content" style="display:none;">
                    <strong>🔐 ZIP File Found:</strong><br>
                    ถ้าพบ ZIP file ที่มี password:<br>
                    • Password อาจซ่อนอยู่ในรูปภาพ<br>
                    • ลองดู strings หรือ comment<br>
                    • Password hint: "whiteflag"
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="stegoFlagFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('stegoFlag')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="stegoSuccess"></div>
            <div class="error-message" id="stegoError"></div>
        `
    },
    //Network 1
    packetBasic: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">📡 Packet Sniffer Basic</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>คุณได้รับไฟล์ pcap ที่บันทึก network traffic ต้องวิเคราะห์หา credentials ที่ส่งผ่าน HTTP</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • File: network_capture.pcap<br>
                    • มี HTTP traffic ที่มี login credentials<br>
                    • ใช้ tcpdump หรือ tshark วิเคราะห์<br>
                    • Flag ซ่อนอยู่ใน POST request data
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">analyst@wireshark:~/captures — bash</span>
                </div>
                <div id="packetTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           PACKET ANALYSIS WORKSTATION                        │
    │           Network Traffic Analyzer                           │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Capture file loaded: network_capture.pcap (156 packets)</span>
    <span style="color: #7ee787;">Available commands:</span>
    tcpdump, tshark, strings, file, capinfos
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="packetCommand" placeholder="tcpdump -r network_capture.pcap" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executePacketCommand();">
                    <button onclick="executePacketCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('packethint1')">💡 Hint 1: Basic Commands (-10 pts)</button>
                <div id="packethint1" class="hint-content" style="display:none;">
                    <strong>📊 Packet Analysis:</strong><br>
                    • <code>tcpdump -r capture.pcap</code> - list packets<br>
                    • <code>tcpdump -r capture.pcap -A</code> - ASCII content<br>
                    • <code>tshark -r capture.pcap</code> - detailed view<br>
                    • <code>capinfos capture.pcap</code> - file info
                </div>

                <button class="hint-btn" onclick="toggleHint('packethint2')">💡 Hint 2: HTTP Filter (-10 pts)</button>
                <div id="packethint2" class="hint-content" style="display:none;">
                    <strong>🌐 HTTP Traffic:</strong><br>
                    • <code>tshark -r capture.pcap -Y "http"</code><br>
                    • <code>tshark -r capture.pcap -Y "http.request.method == POST"</code><br>
                    • มองหา login credentials ใน POST data
                </div>

                <button class="hint-btn" onclick="toggleHint('packethint3')">💡 Hint 3: Extract Data (-10 pts)</button>
                <div id="packethint3" class="hint-content" style="display:none;">
                    <strong>📤 Extract POST Data:</strong><br>
                    <code>tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data</code><br><br>
                    หรือใช้ strings:<br>
                    <code>strings capture.pcap | grep -i password</code>
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="packetBasicFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('packetBasic')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="packetSuccess"></div>
            <div class="error-message" id="packetError"></div>
        `
    },
    //Network 2
    dnsTunnel: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">📡 DNS Tunneling Extract</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>พบ DNS traffic ที่น่าสงสัย ข้อมูลถูก exfiltrate ผ่าน DNS queries ต้องวิเคราะห์และถอดรหัสข้อมูล</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • File: dns_traffic.pcap<br>
                    • มี suspicious DNS queries<br>
                    • Data ถูก encode เป็น Base64 ใน subdomain<br>
                    • รวม subdomains แล้ว decode เพื่อหา flag
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">analyst@wireshark:~/captures — bash</span>
                </div>
                <div id="dnsTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           DNS TRAFFIC ANALYZER                               │
    │           Data Exfiltration Detection                        │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Capture file loaded: dns_traffic.pcap (89 packets)</span>
    <span style="color: #f97583;">⚠ Suspicious DNS activity detected!</span>
    <span style="color: #7ee787;">Available commands:</span>
    tshark, tcpdump, dig, strings, base64
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="dnsCommand" placeholder="tshark -r dns_traffic.pcap -Y dns" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeDNSCommand();">
                    <button onclick="executeDNSCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('dnshint1')">💡 Hint 1: DNS Analysis (-10 pts)</button>
                <div id="dnshint1" class="hint-content" style="display:none;">
                    <strong>🔍 DNS Commands:</strong><br>
                    • <code>tshark -r dns_traffic.pcap -Y "dns"</code><br>
                    • มองหา queries ที่มี subdomain แปลกๆ<br>
                    • Data exfil มักใช้ format: data.evil.com
                </div>

                <button class="hint-btn" onclick="toggleHint('dnshint2')">💡 Hint 2: Extract Subdomains (-10 pts)</button>
                <div id="dnshint2" class="hint-content" style="display:none;">
                    <strong>📤 Extract DNS Queries:</strong><br>
                    <code>tshark -r dns_traffic.pcap -Y "dns.qry.name contains exfil" -T fields -e dns.qry.name</code><br><br>
                    จะได้ subdomains ที่มี encoded data
                </div>

                <button class="hint-btn" onclick="toggleHint('dnshint3')">💡 Hint 3: Decode Data (-10 pts)</button>
                <div id="dnshint3" class="hint-content" style="display:none;">
                    <strong>🔓 Base64 Decode:</strong><br>
                    1. รวม subdomains ทั้งหมด<br>
                    2. ตัด ".exfil.malicious.com" ออก<br>
                    3. รวมเป็น string เดียว<br>
                    4. <code>echo "string" | base64 -d</code>
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="dnsTunnelFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('dnsTunnel')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="dnsSuccess"></div>
            <div class="error-message" id="dnsError"></div>
        `
    },
    //Network 3
    arpSpoof: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">📡 ARP Spoofing Attack Analysis</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>Network team รายงานว่ามี ARP spoofing attack ต้องวิเคราะห์ pcap เพื่อหา attacker และข้อมูลที่ถูกขโมย</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • File: arp_attack.pcap<br>
                    • มี ARP poisoning traffic<br>
                    • Attacker intercept HTTP credentials<br>
                    • ต้องหา attacker MAC และ stolen data
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">analyst@soc:~/incidents — bash</span>
                </div>
                <div id="arpTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           ARP ATTACK FORENSICS                               │
    │           Man-in-the-Middle Detection                        │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #f97583;">⚠ ALERT: ARP spoofing detected in capture!</span>
    <span style="color: #8b949e;">Capture file loaded: arp_attack.pcap (234 packets)</span>
    <span style="color: #7ee787;">Available commands:</span>
    tshark, tcpdump, arp, strings, grep
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="arpCommand" placeholder="tshark -r arp_attack.pcap -Y arp" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeArpCommand();">
                    <button onclick="executeArpCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('arphint1')">💡 Hint 1: ARP Analysis (-10 pts)</button>
                <div id="arphint1" class="hint-content" style="display:none;">
                    <strong>🔍 ARP Commands:</strong><br>
                    • <code>tshark -r arp_attack.pcap -Y "arp"</code><br>
                    • <code>tshark -r arp_attack.pcap -Y "arp.opcode == 2"</code> (replies)<br>
                    • มองหา duplicate IP-MAC mappings
                </div>

                <button class="hint-btn" onclick="toggleHint('arphint2')">💡 Hint 2: Identify Attacker (-10 pts)</button>
                <div id="arphint2" class="hint-content" style="display:none;">
                    <strong>🎭 Attacker Detection:</strong><br>
                    • หา MAC address ที่ claim เป็นหลาย IPs<br>
                    • หา gratuitous ARP packets<br>
                    • <code>tshark -r arp_attack.pcap -Y "arp" -T fields -e eth.src -e arp.src.proto_ipv4</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('arphint3')">💡 Hint 3: Stolen Data (-10 pts)</button>
                <div id="arphint3" class="hint-content" style="display:none;">
                    <strong>📤 Extract Intercepted Data:</strong><br>
                    หลังจากหา attacker MAC แล้ว:<br>
                    • Filter HTTP traffic from attacker<br>
                    • <code>tshark -r arp_attack.pcap -Y "http && eth.src == AA:BB:CC:DD:EE:FF"</code><br>
                    • Flag อยู่ใน intercepted credentials
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="arpSpoofFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('arpSpoof')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="arpSuccess"></div>
            <div class="error-message" id="arpError"></div>
        `
    },
    //Reversing 1
    asmPassword: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">⚙️ Assembly Password Check</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>วิเคราะห์ assembly code ที่ใช้ตรวจสอบ password เพื่อหา correct password</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • Binary: password_checker<br>
                    • มี simple password check ใน assembly<br>
                    • ต้องอ่าน assembly และหา password ที่ถูกต้อง<br>
                    • Flag format: secXplore{password}
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">reverser@workstation:~/binaries — bash</span>
                </div>
                <div id="asmTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           REVERSE ENGINEERING WORKSTATION                    │
    │           x86-64 Assembly Analyzer                           │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Binary loaded: password_checker (ELF 64-bit LSB executable)</span>
    <span style="color: #7ee787;">Available commands:</span>
    objdump, strings, file, readelf, ltrace, strace, gdb, r2
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="asmCommand" placeholder="objdump -d password_checker" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeAsmCommand();">
                    <button onclick="executeAsmCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('asmhint1')">💡 Hint 1: Disassembly (-10 pts)</button>
                <div id="asmhint1" class="hint-content" style="display:none;">
                    <strong>🔧 Basic Commands:</strong><br>
                    • <code>objdump -d password_checker</code> - disassemble<br>
                    • <code>strings password_checker</code> - find strings<br>
                    • <code>file password_checker</code> - file info
                </div>

                <button class="hint-btn" onclick="toggleHint('asmhint2')">💡 Hint 2: Finding Password (-10 pts)</button>
                <div id="asmhint2" class="hint-content" style="display:none;">
                    <strong>🔍 Look for:</strong><br>
                    • strcmp หรือ strncmp calls<br>
                    • mov instructions ที่โหลด string addresses<br>
                    • cmp instructions เปรียบเทียบ values<br>
                    • ลอง <code>strings password_checker | grep -i pass</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('asmhint3')">💡 Hint 3: Assembly Analysis (-10 pts)</button>
                <div id="asmhint3" class="hint-content" style="display:none;">
                    <strong>📝 Key Instructions:</strong><br>
                    ดู check_password function:<br>
                    • lea rdi, [correct_password]<br>
                    • call strcmp<br><br>
                    Password อยู่ใน .rodata section
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="asmPasswordFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('asmPassword')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="asmSuccess"></div>
            <div class="error-message" id="asmError"></div>
        `
    },
    //Reversing 2
    crackme: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">⚙️ Binary Crackme</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>Crack binary นี้เพื่อหา serial number ที่ถูกต้อง โปรแกรมใช้ algorithm ง่ายๆ ในการ validate</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • Binary: crackme_easy<br>
                    • ต้องหา valid serial number<br>
                    • Algorithm: XOR และ comparison<br>
                    • เมื่อใส่ serial ถูกต้องจะแสดง flag
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">reverser@workstation:~/binaries — bash</span>
                </div>
                <div id="crackmeTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           CRACKME CHALLENGE                                  │
    │           Serial Key Validator                               │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Binary loaded: crackme_easy (ELF 64-bit LSB executable)</span>
    <span style="color: #7ee787;">Available commands:</span>
    objdump, strings, file, readelf, ltrace, strace, gdb, r2, ./crackme_easy
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="crackmeCommand" placeholder="./crackme_easy SERIAL123" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeCrackmeCommand();">
                    <button onclick="executeCrackmeCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('crackmehint1')">💡 Hint 1: Dynamic Analysis (-10 pts)</button>
                <div id="crackmehint1" class="hint-content" style="display:none;">
                    <strong>🔧 Commands:</strong><br>
                    • <code>ltrace ./crackme_easy TEST</code> - trace library calls<br>
                    • <code>strace ./crackme_easy TEST</code> - trace syscalls<br>
                    • <code>strings crackme_easy</code> - find strings
                </div>

                <button class="hint-btn" onclick="toggleHint('crackmehint2')">💡 Hint 2: Algorithm (-10 pts)</button>
                <div id="crackmehint2" class="hint-content" style="display:none;">
                    <strong>🔢 Serial Validation:</strong><br>
                    • Serial ถูก XOR กับ key<br>
                    • ผลลัพธ์ต้องเท่ากับ expected value<br>
                    • ใช้ <code>objdump -d</code> ดู algorithm
                </div>

                <button class="hint-btn" onclick="toggleHint('crackmehint3')">💡 Hint 3: Solution (-10 pts)</button>
                <div id="crackmehint3" class="hint-content" style="display:none;">
                    <strong>✅ Steps:</strong><br>
                    1. หา expected value จาก disassembly<br>
                    2. หา XOR key<br>
                    3. XOR expected กับ key = serial<br>
                    4. ลอง: <code>./crackme_easy R3V3RS3</code>
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="crackmeFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('crackme')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="crackmeSuccess"></div>
            <div class="error-message" id="crackmeError"></div>
        `
    },
    //Reversing 3
    obfuscated: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">⚙️ Obfuscated Code Analysis</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>พบ JavaScript code ที่ถูก obfuscate อย่างหนัก ต้องวิเคราะห์และถอดรหัสเพื่อหา hidden flag</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • File: obfuscated.js<br>
                    • JavaScript ถูก obfuscate<br>
                    • มี hidden flag ซ่อนอยู่ใน code<br>
                    • ต้อง deobfuscate และวิเคราะห์ logic
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">analyst@workstation:~/scripts — node</span>
                </div>
                <div id="obfuscatedTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           JS DEOBFUSCATION WORKBENCH                         │
    │           Code Analysis Tool                                 │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">File loaded: obfuscated.js</span>
    <span style="color: #7ee787;">Available commands:</span>
    cat, beautify, deobfuscate, decode, eval, strings
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="obfuscatedCommand" placeholder="cat obfuscated.js" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeObfuscatedCommand();">
                    <button onclick="executeObfuscatedCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('obfuscatedhint1')">💡 Hint 1: View Code (-10 pts)</button>
                <div id="obfuscatedhint1" class="hint-content" style="display:none;">
                    <strong>👁️ View Commands:</strong><br>
                    • <code>cat obfuscated.js</code> - view raw code<br>
                    • <code>beautify obfuscated.js</code> - format code<br>
                    • มองหา patterns ที่น่าสงสัย
                </div>

                <button class="hint-btn" onclick="toggleHint('obfuscatedhint2')">💡 Hint 2: Deobfuscation (-10 pts)</button>
                <div id="obfuscatedhint2" class="hint-content" style="display:none;">
                    <strong>🔓 Techniques:</strong><br>
                    • หา eval() หรือ Function() calls<br>
                    • Base64 decoded strings<br>
                    • Hex encoded values<br>
                    • <code>deobfuscate obfuscated.js</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('obfuscatedhint3')">💡 Hint 3: Extract Flag (-10 pts)</button>
                <div id="obfuscatedhint3" class="hint-content" style="display:none;">
                    <strong>🏴 Find Flag:</strong><br>
                    • <code>strings obfuscated.js | grep -i sec</code><br>
                    • <code>decode base64 [encoded_string]</code><br>
                    • Flag มักซ่อนใน Base64 หรือ hex
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="obfuscatedFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('obfuscated')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="obfuscatedSuccess"></div>
            <div class="error-message" id="obfuscatedError"></div>
        `
    },
    //Moblile 1
    apkStrings: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">📱 APK String Analysis</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>วิเคราะห์ Android APK file เพื่อหา hardcoded credentials และ secrets</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • File: suspicious_app.apk<br>
                    • Developer hardcode secrets ไว้ใน app<br>
                    • ต้องหา API keys, passwords หรือ flags<br>
                    • ใช้ apktool, jadx, strings วิเคราะห์
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">mobile@analyst:~/apks — bash</span>
                </div>
                <div id="apkTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           ANDROID APK ANALYZER                               │
    │           Mobile Security Workstation                        │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">APK loaded: suspicious_app.apk (4.2 MB)</span>
    <span style="color: #7ee787;">Available commands:</span>
    apktool, jadx, strings, unzip, file, grep, find, aapt
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="apkCommand" placeholder="strings suspicious_app.apk | grep -i flag" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeApkCommand();">
                    <button onclick="executeApkCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('apkhint1')">💡 Hint 1: Extract APK (-10 pts)</button>
                <div id="apkhint1" class="hint-content" style="display:none;">
                    <strong>📦 Extraction:</strong><br>
                    • <code>apktool d suspicious_app.apk</code> - decompile<br>
                    • <code>unzip suspicious_app.apk -d output/</code><br>
                    • <code>jadx suspicious_app.apk</code> - decompile to Java
                </div>

                <button class="hint-btn" onclick="toggleHint('apkhint2')">💡 Hint 2: Find Secrets (-10 pts)</button>
                <div id="apkhint2" class="hint-content" style="display:none;">
                    <strong>🔍 Search Commands:</strong><br>
                    • <code>strings suspicious_app.apk | grep -i api</code><br>
                    • <code>strings suspicious_app.apk | grep -i key</code><br>
                    • <code>strings suspicious_app.apk | grep -i sec</code><br>
                    • ดู res/values/strings.xml
                </div>

                <button class="hint-btn" onclick="toggleHint('apkhint3')">💡 Hint 3: Common Locations (-10 pts)</button>
                <div id="apkhint3" class="hint-content" style="display:none;">
                    <strong>📁 Check These:</strong><br>
                    • res/values/strings.xml<br>
                    • assets/ folder<br>
                    • BuildConfig.java<br>
                    • SharedPreferences defaults
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="apkAnalysisFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('apkStrings')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="apkSuccess"></div>
            <div class="error-message" id="apkError"></div>
        `
    },
    //Mobile 2
    rootBypass: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">📱 Root Detection Bypass</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>App มี root detection ที่ป้องกันไม่ให้ทำงานบน rooted device ต้อง bypass เพื่อเข้าถึง hidden feature</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • App: SecureBank.apk<br>
                    • มี root detection หลายระดับ<br>
                    • ต้อง bypass เพื่อเข้าถึง debug menu<br>
                    • Debug menu มี flag ซ่อนอยู่
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">mobile@analyst:~/apks — frida</span>
                </div>
                <div id="rootTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           ROOT DETECTION BYPASS LAB                          │
    │           Frida Instrumentation Framework                    │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Target: SecureBank.apk</span>
    <span style="color: #f97583;">⚠ Root detection active!</span>
    <span style="color: #7ee787;">Available commands:</span>
    jadx, frida, objection, apktool, smali, baksmali
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="rootCommand" placeholder="jadx SecureBank.apk -d output/" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeRootCommand();">
                    <button onclick="executeRootCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('roothint1')">💡 Hint 1: Find Detection Code (-10 pts)</button>
                <div id="roothint1" class="hint-content" style="display:none;">
                    <strong>🔍 Search for:</strong><br>
                    • <code>grep -r "isRooted" output/</code><br>
                    • <code>grep -r "checkRoot" output/</code><br>
                    • <code>grep -r "/su" output/</code><br>
                    • ดู RootDetector.java หรือ SecurityUtils.java
                </div>

                <button class="hint-btn" onclick="toggleHint('roothint2')">💡 Hint 2: Frida Hook (-10 pts)</button>
                <div id="roothint2" class="hint-content" style="display:none;">
                    <strong>🪝 Frida Script:</strong><br>
                    Hook isRooted() function ให้ return false:<br>
                    <code>frida -U -f com.securebank.app -l bypass.js</code><br><br>
                    Script: Java.use("RootDetector").isRooted.implementation = function() { return false; }
                </div>

                <button class="hint-btn" onclick="toggleHint('roothint3')">💡 Hint 3: Smali Patch (-10 pts)</button>
                <div id="roothint3" class="hint-content" style="display:none;">
                    <strong>✏️ Patch Method:</strong><br>
                    1. Decompile: <code>apktool d SecureBank.apk</code><br>
                    2. แก้ smali: เปลี่ยน return-type เป็น false<br>
                    3. Rebuild: <code>apktool b SecureBank/</code><br>
                    4. Sign APK แล้วติดตั้ง
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="rootDetectionFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('rootBypass')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="rootSuccess"></div>
            <div class="error-message" id="rootError"></div>
        `
    },
    //Mobile 3
    sslPinning: {
        content: `
            <h2 style="color: var(--primary); margin-bottom: 1rem;">📱 SSL Pinning Challenge</h2>
            
            <div class="analysis-results">
                <h4>🎯 Mission Briefing</h4>
                <p>App มี SSL Certificate Pinning ที่ป้องกัน MITM attack ต้อง bypass เพื่อ intercept traffic</p>
                
                <div style="background: rgba(255,170,0,0.1); border-left: 3px solid var(--warning); padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                    <strong>📋 Scenario:</strong><br>
                    • App: SecretChat.apk<br>
                    • มี SSL Pinning implementation<br>
                    • ต้อง bypass เพื่อ intercept HTTPS traffic<br>
                    • API response มี flag ซ่อนอยู่
                </div>
            </div>

            <div class="terminal" style="background: #0d1117; border: 2px solid var(--primary); border-radius: 10px; overflow: hidden;">
                <div class="terminal-header" style="background: #161b22; padding: 0.8rem 1rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem;">
                    <div style="display: flex; gap: 6px;">
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
                        <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
                    </div>
                    <span style="color: #8b949e; font-size: 0.85rem; margin-left: 1rem;">mobile@analyst:~/ssl — frida + burp</span>
                </div>
                <div id="sslTerminal" class="terminal-output" style="padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; min-height: 350px; max-height: 450px; overflow-y: auto; color: #c9d1d9; background: #0d1117; line-height: 1.5;">
    <span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
    │           SSL PINNING BYPASS LAB                             │
    │           Certificate Pinning Analysis                       │
    └──────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Target: SecretChat.apk</span>
    <span style="color: #f97583;">⚠ SSL Certificate Pinning detected!</span>
    <span style="color: #7ee787;">Available commands:</span>
    jadx, frida, objection, apktool, openssl, burp
    <span style="color: #f0883e;">────────────────────────────────────────────────────────────────</span>
    <span style="color: #8b949e;">$ </span></div>
                <div style="display: flex; padding: 0.8rem 1rem; gap: 0.5rem; background: #161b22; border-top: 1px solid #30363d;">
                    <span style="color: #7ee787; font-family: monospace;">$</span>
                    <input type="text" id="sslCommand" placeholder="jadx SecretChat.apk -d output/" 
                        style="flex: 1; background: transparent; border: none; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 0.9rem; outline: none;"
                        onkeypress="if(event.key==='Enter') executeSslCommand();">
                    <button onclick="executeSslCommand()" style="background: var(--primary); color: #0d1117; border: none; padding: 0.5rem 1.2rem; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 0.85rem;">Run</button>
                </div>
            </div>

            <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('sslhint1')">💡 Hint 1: Find Pinning Code (-10 pts)</button>
                <div id="sslhint1" class="hint-content" style="display:none;">
                    <strong>🔍 Common Implementations:</strong><br>
                    • OkHttp CertificatePinner<br>
                    • TrustManager custom implementation<br>
                    • Network Security Config<br><br>
                    <code>grep -r "CertificatePinner" output/</code><br>
                    <code>grep -r "TrustManager" output/</code>
                </div>

                <button class="hint-btn" onclick="toggleHint('sslhint2')">💡 Hint 2: Objection Bypass (-10 pts)</button>
                <div id="sslhint2" class="hint-content" style="display:none;">
                    <strong>🪝 Objection Commands:</strong><br>
                    <code>objection -g com.secretchat.app explore</code><br>
                    <code>android sslpinning disable</code><br><br>
                    หรือใช้ Frida script สำหรับ bypass
                </div>

                <button class="hint-btn" onclick="toggleHint('sslhint3')">💡 Hint 3: Intercept Traffic (-10 pts)</button>
                <div id="sslhint3" class="hint-content" style="display:none;">
                    <strong>📡 After Bypass:</strong><br>
                    1. Setup Burp proxy<br>
                    2. Install Burp CA cert<br>
                    3. Run frida bypass script<br>
                    4. Intercept /api/secret endpoint<br>
                    5. Flag อยู่ใน response body
                </div>
            </div>

            <div class="flag-input">
                <input type="text" id="sslPinningFlag" placeholder="secXplore{...}">
                <button class="submit-btn" onclick="checkFlag('sslPinning')">🚀 Submit Flag</button>
            </div>
            <div class="success-message" id="sslPinSuccess"></div>
            <div class="error-message" id="sslPinError"></div>
        `
    }
};

// ============================================
// 5. HELPER FUNCTIONS & SIMULATION LOGIC
// ============================================

// --- UI Helpers ---
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function showError(element, message) {
    if (element) {
        element.style.display = 'block';
        element.textContent = message;
        setTimeout(() => element.style.display = 'none', 3000);
    }
}

function updatePointsDisplay() {
    if (currentUser) {
        // Update elements in interactive modals
        const points = document.querySelectorAll('.current-points');
        points.forEach(el => el.textContent = currentUser.score);
    }
}

function createParticles() {
    const particlesContainer = document.getElementById('particles');
    if (!particlesContainer) return;
    particlesContainer.innerHTML = '';
    for (let i = 0; i < 100; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 15 + 's';
        particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
        particlesContainer.appendChild(particle);
    }
}

// --- Confirmation Dialog Logic ---
function showHintConfirmation(hintId, pointDeduction, onConfirm) {
    const confirmDialog = document.createElement('div');
    confirmDialog.className = 'confirm-overlay';
    const hintNumber = hintId.match(/hint(\d+)$/)?.[1] || '?';
    
    confirmDialog.innerHTML = `
        <div class="confirm-dialog">
            <h3>⚠️ ยืนยันการใช้ Hint ${hintNumber}</h3>
            <p>การเปิด hint นี้จะหัก <strong style="color: var(--danger);">${pointDeduction} คะแนน</strong></p>
            <div class="confirm-buttons">
                <button class="btn-cancel" onclick="closeHintConfirmDialog()">ยกเลิก</button>
                <button class="btn-confirm" onclick="confirmHint()">ยืนยัน</button>
            </div>
        </div>
    `;
    document.body.appendChild(confirmDialog);
    window.hintConfirmCallback = onConfirm;
    setTimeout(() => confirmDialog.classList.add('show'), 10);
}

function closeHintConfirmDialog() {
    const dialog = document.querySelector('.confirm-overlay');
    if (dialog) {
        dialog.classList.remove('show');
        setTimeout(() => dialog.remove(), 300);
    }
    delete window.hintConfirmCallback;
}

window.confirmHint = function() {
    if (window.hintConfirmCallback) window.hintConfirmCallback();
    closeHintConfirmDialog();
};

// ============================================
// 6. INTERACTIVE CHALLENGE LOGIC (from challenge1.js)
// ============================================

// Web Security - SQL Injection
window.attemptSQLLogin = function() {
    const username = document.getElementById('sqlUser').value;
    const password = document.getElementById('sqlPass').value;
    const resultDiv = document.getElementById('sqlResult');
    const debugDiv = document.getElementById('sqlDebug');
    
    // Build query for debug display
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    
    // Show debug info
    debugDiv.innerHTML = `
        <div style="color: var(--secondary); margin-bottom: 0.5rem;">📝 Generated Query:</div>
        <code style="color: var(--primary); word-break: break-all; display: block; padding: 0.5rem; background: rgba(0,0,0,0.5); border-radius: 4px; font-size: 0.85rem;">${escapeHtml(query)}</code>
        <div style="color: var(--gray); font-size: 0.8rem; margin-top: 0.5rem;">⏱ ${new Date().toLocaleTimeString()}</div>
    `;
    
    // WAF Filter Check (case-sensitive exact match)
    const blockedExact = ['OR', 'AND', '--', '/*'];
    const input = username + password;
    
    for (let pattern of blockedExact) {
        if (input.includes(pattern)) {
            resultDiv.innerHTML = `
                <div style="color: var(--danger); padding: 1rem; border: 1px solid var(--danger); border-radius: 8px; margin-top: 1rem; background: rgba(255,0,0,0.1);">
                    🛡️ <strong>WAF BLOCKED!</strong><br>
                    <span style="font-size: 0.9rem;">Blocked pattern detected: "${pattern}"</span>
                </div>
            `;
            debugDiv.innerHTML += `<div style="color: var(--danger); margin-top: 0.5rem;">⚠️ WAF Rule Triggered: "${pattern}"</div>`;
            return;
        }
    }
    
    // SQL Injection Success Patterns (case-insensitive OR/And bypass)
    const successPatterns = [
        /admin['"]?\s*[oO][rR]\s*['"]?1['"]?\s*=\s*['"]?1/i,
        /admin['"]?\s*\|\|\s*['"]?1['"]?\s*=\s*['"]?1/i,
        /['"]?\s*[oO][rR]\s*['"]?1['"]?\s*=\s*['"]?1/i,
        /['"]?\s*[oO][rR]\s*1\s*=\s*1/i,
        /admin['"]?\s*[oO][rR]\s*true/i,
        /['"]?\s*\|\|\s*1\s*=\s*1/i,
        /admin['"]?\s*[oO][rR]\s*['"]?[^']*['"]?\s*=\s*['"]?[^']*['"]/i
    ];
    
    const isSuccess = successPatterns.some(p => p.test(username) || p.test(input));
    
    if (isSuccess) {
        resultDiv.innerHTML = `
            <div style="color: var(--success); padding: 1.5rem; border: 2px solid var(--success); border-radius: 8px; margin-top: 1rem; background: rgba(0,255,136,0.1);">
                ✅ <strong>LOGIN SUCCESSFUL!</strong><br><br>
                <div style="background: rgba(0,0,0,0.5); padding: 1rem; border-radius: 8px;">
                    👤 Welcome, <strong style="color: var(--primary);">Administrator</strong><br>
                    📧 admin@securebank.com<br>
                    🔑 Role: SUPER_ADMIN<br>
                    💰 Balance: $1,337,420.69<br><br>
                    🏴 <strong>FLAG:</strong> <code style="background: var(--primary); color: var(--dark); padding: 0.3rem 0.6rem; border-radius: 4px;">secXplore{sql_1nj3ct10n_byp4ss_ez}</code>
                </div>
            </div>
        `;
        debugDiv.innerHTML += `<div style="color: var(--success); margin-top: 0.5rem;">✅ SQL Injection successful - Authentication bypassed!</div>`;
    } else if (username === 'admin' && password === 'admin') {
        resultDiv.innerHTML = `
            <div style="color: var(--warning); padding: 1rem; border: 1px solid var(--warning); border-radius: 8px; margin-top: 1rem;">
                ⚠️ Nice guess, but the password was changed!<br>
                <span style="color: var(--gray); font-size: 0.9rem;">Hint: Try SQL Injection techniques...</span>
            </div>
        `;
    } else {
        resultDiv.innerHTML = `
            <div style="color: var(--danger); padding: 1rem; border: 1px solid var(--danger); border-radius: 8px; margin-top: 1rem;">
                ❌ <strong>Login Failed</strong><br>
                <span style="font-size: 0.9rem;">Invalid username or password</span>
            </div>
        `;
    }
};

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Web Security - Command Injection
window.executeCMD = function() {
    const input = document.getElementById('cmdInput');
    const command = input.value.trim();
    const terminal = document.getElementById('cmdTerminal');
    
    if (!command) return;
    
    // Append command to terminal
    terminal.innerHTML += `\n<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // ============== HELP ==============
    if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ping [host]           - Ping a host (vulnerable to injection!)
  ls [-la] [path]       - List directory contents
  cat [file]            - Display file contents
  head [-n N] [file]    - Display first N lines
  tail [-n N] [file]    - Display last N lines
  pwd                   - Print working directory
  cd [path]             - Change directory (simulated)
  whoami                - Display current user
  id                    - Display user/group IDs
  uname [-a]            - System information
  hostname              - Display hostname
  uptime                - System uptime
  date                  - Display date/time
  find [path] -name [pattern]  - Search for files
  grep [-r] [pattern] [file]   - Search in files
  wc [-l] [file]        - Count lines/words
  file [name]           - Determine file type
  which [cmd]           - Locate command
  env                   - Environment variables
  echo [text]           - Print text
  ps [aux]              - List processes
  netstat [-tlnp]       - Network connections
  ifconfig / ip addr    - Network interfaces
  curl [url]            - HTTP request (limited)
  wget [url]            - Download file (limited)
  base64 [-d] [text]    - Base64 encode/decode
  md5sum [file]         - Calculate MD5 hash
  sha256sum [file]      - Calculate SHA256 hash
  history               - Command history
  clear                 - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // ============== CLEAR ==============
    else if (cmd === 'clear' || cmd === 'cls') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           NETWORK DIAGNOSTIC TOOL v2.1                       │
│           Authorized Personnel Only                          │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">Terminal cleared. Type 'help' for available commands.</span>
`;
        input.value = '';
        return;
    }
    // ============== PING (vulnerable) ==============
    else if (cmd.startsWith('ping ') && !cmd.includes(';') && !cmd.includes('|') && !cmd.includes('&') && !cmd.includes('`') && !cmd.includes('$(')) {
        const target = command.substring(5).trim().split(' ')[0];
        terminal.innerHTML += `<span style="color: #8b949e;">PING ${target} (${target === 'localhost' || target === '127.0.0.1' ? '127.0.0.1' : '93.184.216.34'}) 56(84) bytes of data.
64 bytes from ${target}: icmp_seq=1 ttl=64 time=0.028 ms
64 bytes from ${target}: icmp_seq=2 ttl=64 time=0.031 ms
64 bytes from ${target}: icmp_seq=3 ttl=64 time=0.029 ms
64 bytes from ${target}: icmp_seq=4 ttl=64 time=0.032 ms

--- ${target} ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 0.028/0.030/0.032/0.001 ms
</span>`;
    }
    // ============== WHOAMI ==============
    else if (cmd === 'whoami') {
        terminal.innerHTML += `www-data\n`;
    }
    // ============== ID ==============
    else if (cmd === 'id') {
        terminal.innerHTML += `uid=33(www-data) gid=33(www-data) groups=33(www-data)\n`;
    }
    // ============== HOSTNAME ==============
    else if (cmd === 'hostname') {
        terminal.innerHTML += `diagnostic-server\n`;
    }
    // ============== UNAME ==============
    else if (cmd.startsWith('uname')) {
        if (cmd.includes('-a')) {
            terminal.innerHTML += `Linux diagnostic-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n`;
        } else if (cmd.includes('-r')) {
            terminal.innerHTML += `5.15.0-91-generic\n`;
        } else if (cmd.includes('-s')) {
            terminal.innerHTML += `Linux\n`;
        } else if (cmd.includes('-m')) {
            terminal.innerHTML += `x86_64\n`;
        } else {
            terminal.innerHTML += `Linux\n`;
        }
    }
    // ============== PWD ==============
    else if (cmd === 'pwd') {
        terminal.innerHTML += `/var/www/html\n`;
    }
    // ============== DATE ==============
    else if (cmd === 'date') {
        terminal.innerHTML += `${new Date().toString()}\n`;
    }
    // ============== UPTIME ==============
    else if (cmd === 'uptime') {
        terminal.innerHTML += ` ${new Date().toLocaleTimeString()} up 47 days, 3:22, 1 user, load average: 0.08, 0.03, 0.01\n`;
    }
    // ============== ENV ==============
    else if (cmd === 'env' || cmd === 'printenv') {
        terminal.innerHTML += `<span style="color: #8b949e;">SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/var/www/html
HOME=/var/www
USER=www-data
LOGNAME=www-data
LANG=en_US.UTF-8
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
SERVER_SOFTWARE=Apache/2.4.52 (Ubuntu)
DOCUMENT_ROOT=/var/www/html
REMOTE_ADDR=192.168.1.100
SERVER_ADDR=192.168.1.50
SERVER_PORT=80
</span>`;
    }
    // ============== PS ==============
    else if (cmd.includes('ps')) {
        terminal.innerHTML += `<span style="color: #8b949e;">USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168940 11424 ?        Ss   00:00   0:03 /sbin/init
root       245  0.0  0.1  72308  6144 ?        Ss   00:00   0:00 /usr/sbin/sshd -D
root       412  0.0  0.2 214340 18456 ?        Ss   00:00   0:02 /usr/sbin/apache2 -k start
www-data   845  0.0  0.1 214816  9628 ?        S    00:01   0:01 /usr/sbin/apache2 -k start
www-data   846  0.0  0.1 214816  9628 ?        S    00:01   0:01 /usr/sbin/apache2 -k start
mysql      923  0.2  2.5 1842524 165432 ?      Ssl  00:01   0:18 /usr/sbin/mysqld
www-data  1847  0.0  0.0   2608   536 ?        S    10:30   0:00 sh -c ping 127.0.0.1
www-data  1848  0.0  0.0   9424  3348 ?        R    10:30   0:00 ps aux
</span>`;
    }
    // ============== NETSTAT ==============
    else if (cmd.includes('netstat')) {
        terminal.innerHTML += `<span style="color: #8b949e;">Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      245/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      412/apache2
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      923/mysqld
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      412/apache2
udp        0      0 0.0.0.0:68              0.0.0.0:*                           342/dhclient
</span>`;
    }
    // ============== IFCONFIG / IP ==============
    else if (cmd === 'ifconfig' || cmd === 'ip addr' || cmd === 'ip a') {
        terminal.innerHTML += `<span style="color: #8b949e;">eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe8d:c04d  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:8d:c0:4d  txqueuelen 1000  (Ethernet)
        RX packets 28459  bytes 30541872 (30.5 MB)
        TX packets 12983  bytes 1847293 (1.8 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
</span>`;
    }
    // ============== LS ==============
    else if (cmd.match(/^ls|;\s*ls|&&\s*ls|\|\s*ls|\|\|\s*ls/)) {
        let output = '';
        if (cmd.includes('/var/www/app/secret') || cmd.includes('secret')) {
            output = cmd.includes('-l') || cmd.includes('-la') ? 
`<span style="color: #8b949e;">total 16
drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">.</span>
drwxr-xr-x 4 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">..</span>
-rw-r--r-- 1 www-data www-data  156 Jan 15 10:30 <span style="color: #f97583;">backup.sql</span>
-rw-r--r-- 1 www-data www-data  234 Jan 15 10:30 <span style="color: #f97583;">credentials.txt</span>
-rw-r--r-- 1 root     root      312 Jan 15 10:30 <span style="color: #ffa657;">flag.txt</span>
</span>` : `<span style="color: #8b949e;">backup.sql  credentials.txt  <span style="color: #ffa657;">flag.txt</span></span>\n`;
        } else if (cmd.includes('/var/www/app') || cmd.includes('app')) {
            output = cmd.includes('-l') || cmd.includes('-la') ?
`<span style="color: #8b949e;">total 16
drwxr-xr-x 4 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">.</span>
drwxr-xr-x 3 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">..</span>
drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">logs</span>
drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">public</span>
drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 <span style="color: #ffa657;">secret</span>
</span>` : `<span style="color: #58a6ff;">logs  public  </span><span style="color: #ffa657;">secret</span>\n`;
        } else if (cmd.includes('/var/www') && !cmd.includes('/var/www/html') && !cmd.includes('/var/www/app')) {
            output = cmd.includes('-l') || cmd.includes('-la') ?
`<span style="color: #8b949e;">total 12
drwxr-xr-x 3 root     root     4096 Jan 15 10:30 <span style="color: #58a6ff;">.</span>
drwxr-xr-x 14 root    root     4096 Jan 15 10:30 <span style="color: #58a6ff;">..</span>
drwxr-xr-x 4 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">app</span>
drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">html</span>
</span>` : `<span style="color: #58a6ff;">app  html</span>\n`;
        } else if (cmd.includes('/etc')) {
            output = `<span style="color: #8b949e;">passwd  shadow  hosts  hostname  resolv.conf  apache2  mysql  ssh  ssl  nginx</span>\n`;
        } else if (cmd.includes('/home')) {
            output = `<span style="color: #58a6ff;">admin  user  www-data</span>\n`;
        } else if (cmd.includes('/tmp')) {
            output = `<span style="color: #8b949e;">systemd-private-xxx  apache2-xxx  mysql.sock</span>\n`;
        } else if (cmd.includes('/')) {
            output = `<span style="color: #58a6ff;">bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var</span>\n`;
        } else if (cmd.includes('..')) {
            output = `<span style="color: #58a6ff;">app  html</span>\n`;
        } else {
            // Default: /var/www/html
            output = cmd.includes('-l') || cmd.includes('-la') ?
`<span style="color: #8b949e;">total 32
drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">.</span>
drwxr-xr-x 3 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">..</span>
-rw-r--r-- 1 www-data www-data  892 Jan 15 10:30 .htaccess
-rw-r--r-- 1 www-data www-data 1245 Jan 15 10:30 config.php
-rw-r--r-- 1 www-data www-data 4521 Jan 15 10:30 index.php
-rw-r--r-- 1 www-data www-data  234 Jan 15 10:30 robots.txt
drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">uploads</span>
drwxr-xr-x 2 www-data www-data 4096 Jan 15 10:30 <span style="color: #58a6ff;">assets</span>
</span>` : `<span style="color: #8b949e;">.htaccess  config.php  index.php  robots.txt  </span><span style="color: #58a6ff;">uploads  assets</span>\n`;
        }
        terminal.innerHTML += output;
    }
    // ============== CAT (THE FLAG) ==============
    else if (cmd.match(/cat|;\s*cat|&&\s*cat|\|\s*cat/)) {
        if (cmd.includes('flag.txt') || cmd.includes('/var/www/app/secret/flag')) {
            terminal.innerHTML += `<span style="color: #7ee787;">
╔═══════════════════════════════════════════════════════════════╗
║                    TOP SECRET - CONFIDENTIAL                  ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Congratulations! You have successfully exploited the         ║
║  command injection vulnerability in the ping utility.         ║
║                                                               ║
║  FLAG: secXplore{c0mm4nd_1nj3ct10n_rc3_m4st3r}               ║
║                                                               ║
║  Remember: Always sanitize user input!                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
</span>`;
        } else if (cmd.includes('credentials.txt')) {
            terminal.innerHTML += `<span style="color: #8b949e;">=== Service Credentials (INTERNAL USE ONLY) ===
Database:
  Host: localhost
  User: webapp_user
  Pass: Str0ngDBP@ss2024!

SSH:
  User: admin
  Pass: [REDACTED - See password manager]

API Keys:
  Stripe: sk_live_*************************
  AWS: AKIA********************

Note: The real flag is in flag.txt, not here!
</span>`;
        } else if (cmd.includes('backup.sql')) {
            terminal.innerHTML += `<span style="color: #8b949e;">-- MySQL dump 10.13
-- Database: diagnostic_db
-- 
-- Table structure for table 'users'
CREATE TABLE users (
  id int(11) NOT NULL AUTO_INCREMENT,
  username varchar(50) NOT NULL,
  password varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

INSERT INTO users VALUES (1,'admin','$2y$10$hash...');
-- Flag is not in database, check /var/www/app/secret/
</span>`;
        } else if (cmd.includes('config.php')) {
            terminal.innerHTML += `<span style="color: #8b949e;">&lt;?php
// Database Configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'webapp_user');
define('DB_PASS', '***HIDDEN***');
define('DB_NAME', 'diagnostic_db');

// Security Settings
define('DEBUG_MODE', false);
define('LOG_LEVEL', 'warning');

// Hint: Try exploring /var/www/app/secret/
?&gt;
</span>`;
        } else if (cmd.includes('/etc/passwd')) {
            terminal.innerHTML += `<span style="color: #8b949e;">root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
user:x:1001:1001:Regular User:/home/user:/bin/bash
</span>`;
        } else if (cmd.includes('/etc/shadow')) {
            terminal.innerHTML += `<span style="color: #f97583;">cat: /etc/shadow: Permission denied</span>\n`;
        } else if (cmd.includes('robots.txt')) {
            terminal.innerHTML += `<span style="color: #8b949e;">User-agent: *
Disallow: /admin/
Disallow: /config.php
Disallow: /uploads/
# Secret path: /var/www/app/secret/
</span>`;
        } else {
            const file = command.match(/cat\s+([^\s;|&]+)/)?.[1] || 'unknown';
            terminal.innerHTML += `<span style="color: #f97583;">cat: ${file}: No such file or directory</span>\n`;
        }
    }
    // ============== FIND ==============
    else if (cmd.match(/find|;\s*find|&&\s*find/)) {
        if (cmd.includes('flag') || cmd.includes('*.txt') || cmd.includes('secret')) {
            terminal.innerHTML += `<span style="color: #ffa657;">/var/www/app/secret/flag.txt
/var/www/app/secret/credentials.txt
/var/www/app/secret/backup.sql
/home/user/notes.txt
</span>`;
        } else if (cmd.includes('*.php')) {
            terminal.innerHTML += `<span style="color: #8b949e;">/var/www/html/index.php
/var/www/html/config.php
</span>`;
        } else if (cmd.includes('*.log')) {
            terminal.innerHTML += `<span style="color: #8b949e;">/var/log/apache2/access.log
/var/log/apache2/error.log
/var/www/app/logs/app.log
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">find: missing argument to search\nUsage: find [path] -name [pattern]</span>\n`;
        }
    }
    // ============== GREP ==============
    else if (cmd.match(/grep|;\s*grep|&&\s*grep/)) {
        if (cmd.includes('flag') || cmd.includes('secXplore') || cmd.includes('CTF')) {
            terminal.innerHTML += `<span style="color: #7ee787;">/var/www/app/secret/flag.txt:  FLAG: secXplore{c0mm4nd_1nj3ct10n_rc3_m4st3r}</span>\n`;
        } else if (cmd.includes('password') || cmd.includes('pass')) {
            terminal.innerHTML += `<span style="color: #8b949e;">/var/www/html/config.php:define('DB_PASS', '***HIDDEN***');
/var/www/app/secret/credentials.txt:  Pass: Str0ngDBP@ss2024!
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: grep [pattern] [file]</span>\n`;
        }
    }
    // ============== WHICH ==============
    else if (cmd.startsWith('which ')) {
        const binary = cmd.substring(6).trim();
        const binaries = {
            'ls': '/bin/ls', 'cat': '/bin/cat', 'ping': '/bin/ping',
            'whoami': '/usr/bin/whoami', 'id': '/usr/bin/id', 'find': '/usr/bin/find',
            'grep': '/bin/grep', 'python': '/usr/bin/python3', 'python3': '/usr/bin/python3',
            'bash': '/bin/bash', 'sh': '/bin/sh', 'nc': '/bin/nc', 'netcat': '/bin/nc',
            'curl': '/usr/bin/curl', 'wget': '/usr/bin/wget'
        };
        terminal.innerHTML += binaries[binary] ? `${binaries[binary]}\n` : `<span style="color: #f97583;">${binary} not found</span>\n`;
    }
    // ============== FILE ==============
    else if (cmd.startsWith('file ')) {
        const target = cmd.substring(5).trim();
        if (target.includes('.txt')) {
            terminal.innerHTML += `${target}: ASCII text\n`;
        } else if (target.includes('.php')) {
            terminal.innerHTML += `${target}: PHP script, ASCII text\n`;
        } else if (target.includes('.jpg') || target.includes('.png')) {
            terminal.innerHTML += `${target}: image data\n`;
        } else {
            terminal.innerHTML += `${target}: data\n`;
        }
    }
    // ============== HEAD/TAIL ==============
    else if (cmd.startsWith('head ') || cmd.startsWith('tail ')) {
        terminal.innerHTML += `<span style="color: #8b949e;">Use 'cat' to view complete file contents</span>\n`;
    }
    // ============== ECHO ==============
    else if (cmd.match(/echo|;\s*echo|&&\s*echo/)) {
        const text = command.match(/echo\s+["']?([^"']+)["']?/)?.[1] || '';
        if (cmd.includes('$USER')) {
            terminal.innerHTML += `www-data\n`;
        } else if (cmd.includes('$HOME')) {
            terminal.innerHTML += `/var/www\n`;
        } else if (cmd.includes('$PWD')) {
            terminal.innerHTML += `/var/www/html\n`;
        } else {
            terminal.innerHTML += `${text}\n`;
        }
    }
    // ============== WC ==============
    else if (cmd.startsWith('wc ')) {
        terminal.innerHTML += `  15   45  312 file\n`;
    }
    // ============== HISTORY ==============
    else if (cmd === 'history') {
        terminal.innerHTML += `<span style="color: #8b949e;">    1  ping 127.0.0.1
    2  ls -la
    3  whoami
    4  cat /etc/passwd
    5  history
</span>`;
    }
    // ============== CURL/WGET ==============
    else if (cmd.startsWith('curl ') || cmd.startsWith('wget ')) {
        terminal.innerHTML += `<span style="color: #f97583;">Connection restricted in this environment</span>\n`;
    }
    // ============== BASE64 ==============
    else if (cmd.includes('base64')) {
        if (cmd.includes('-d') && cmd.includes('c2VjWHBsb3Jl')) {
            terminal.innerHTML += `secXplore{decoded}\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: echo "text" | base64 OR echo "encoded" | base64 -d</span>\n`;
        }
    }
    // ============== COMMAND INJECTION CHAINS ==============
    else if (cmd.includes(';') || cmd.includes('|') || cmd.includes('&&') || cmd.includes('||') || cmd.includes('`') || cmd.includes('$(')) {
        // Parse and execute chained commands
        terminal.innerHTML += `<span style="color: #8b949e;">[Executing command chain...]</span>\n`;
        
        // Simple simulation of common chains
        if (cmd.includes('whoami')) terminal.innerHTML += `www-data\n`;
        if (cmd.includes('id') && !cmd.includes('id=')) terminal.innerHTML += `uid=33(www-data) gid=33(www-data) groups=33(www-data)\n`;
        if (cmd.includes('pwd')) terminal.innerHTML += `/var/www/html\n`;
        if (cmd.includes('ls') && !cmd.includes('false')) {
            if (cmd.includes('secret')) {
                terminal.innerHTML += `backup.sql  credentials.txt  flag.txt\n`;
            } else {
                terminal.innerHTML += `.htaccess  config.php  index.php  robots.txt  uploads  assets\n`;
            }
        }
        if (cmd.includes('cat') && cmd.includes('flag')) {
            terminal.innerHTML += `<span style="color: #7ee787;">FLAG: secXplore{c0mm4nd_1nj3ct10n_rc3_m4st3r}</span>\n`;
        }
        if (cmd.includes('uname')) terminal.innerHTML += `Linux\n`;
    }
    // ============== UNKNOWN COMMAND ==============
    else {
        const cmdName = command.split(' ')[0];
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${cmdName}: command not found</span>\n`;
    }
    
    // Scroll to bottom and clear input
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};

// Web Security - XSS Cookie Stealer
window.submitXSS = function() {
    const nameInput = document.getElementById('xssName');
    const commentInput = document.getElementById('xssInput');
    const commentsDiv = document.getElementById('xssComments');
    const resultDiv = document.getElementById('xssResult');
    const filterLog = document.getElementById('xssFilterLog');
    
    const name = nameInput.value.trim() || 'Anonymous';
    const comment = commentInput.value.trim();
    
    if (!comment) {
        filterLog.innerHTML = `<span style="color: var(--warning);">⚠️ Please enter a comment</span>`;
        return;
    }
    
    // XSS Filter Simulation
    let blocked = false;
    let filterMessages = [];
    
    // Blocked patterns
    const blockedPatterns = [
        { pattern: /<script/gi, name: '&lt;script&gt;' },
        { pattern: /onerror\s*=/gi, name: 'onerror=' },
        { pattern: /onclick\s*=/gi, name: 'onclick=' }
    ];
    
    blockedPatterns.forEach(({pattern, name}) => {
        if (pattern.test(comment)) {
            filterMessages.push(`❌ Blocked: ${name}`);
            blocked = true;
        }
    });
    
    // XSS Success Patterns (bypasses)
    const xssSuccessPatterns = [
        /<svg[^>]*onload\s*=/i,
        /<img[^>]*onload\s*=/i,
        /<body[^>]*onload\s*=/i,
        /<body[^>]*onpageshow\s*=/i,
        /<iframe[^>]*onload\s*=/i,
        /<input[^>]*onfocus\s*=[^>]*autofocus/i,
        /<marquee[^>]*onstart\s*=/i,
        /<video[^>]*onloadstart\s*=/i,
        /<details[^>]*ontoggle\s*=[^>]*open/i,
        /<img[^>]*oNLoAd\s*=/i,  // Mixed case bypass
        /<svg[^>]*ONLOAD\s*=/i
    ];
    
    const hasCookieAccess = /document\.cookie/i.test(comment) || 
                           /document\[['"]cookie['"]\]/i.test(comment);
    
    const isXSSSuccess = !blocked && xssSuccessPatterns.some(p => p.test(comment)) && hasCookieAccess;
    
    // Update filter log
    if (filterMessages.length > 0) {
        filterLog.innerHTML = `<span style="color: var(--danger);">${filterMessages.join('<br>')}<br>Your comment was blocked!</span>`;
    } else {
        filterLog.innerHTML = `<span style="color: var(--success);">✅ XSS Filter: PASSED</span>`;
    }
    
    if (blocked) {
        resultDiv.innerHTML = `
            <div style="color: var(--danger); padding: 1rem; border: 1px solid var(--danger); border-radius: 8px; background: rgba(255,0,0,0.1);">
                🛡️ <strong>XSS Filter Triggered!</strong><br>
                <span style="font-size: 0.9rem;">Malicious content detected. Try different payloads!</span>
            </div>
        `;
        return;
    }
    
    // Add comment to list (escaped for display)
    const commentEl = document.createElement('div');
    commentEl.style.cssText = 'background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; border-left: 3px solid var(--secondary);';
    commentEl.innerHTML = `
        <div style="color: var(--primary); font-weight: bold; margin-bottom: 0.3rem;">👤 ${escapeHtml(name)}</div>
        <div style="color: var(--light); font-size: 0.9rem; word-break: break-all;">${escapeHtml(comment)}</div>
        <div style="color: var(--gray); font-size: 0.75rem; margin-top: 0.5rem;">📅 ${new Date().toLocaleString()}</div>
    `;
    commentsDiv.prepend(commentEl);
    
    if (isXSSSuccess) {
        // Simulate admin visiting
        resultDiv.innerHTML = `
            <div style="color: var(--warning); padding: 1rem; border: 1px solid var(--warning); border-radius: 8px; background: rgba(255,170,0,0.1);">
                ⏳ <strong>Comment posted!</strong> Waiting for admin to view page...
            </div>
        `;
        
        setTimeout(() => {
            resultDiv.innerHTML = `
                <div style="color: var(--secondary); padding: 1rem; border: 1px solid var(--secondary); border-radius: 8px;">
                    👀 Admin is viewing the page...
                </div>
            `;
        }, 1500);
        
        setTimeout(() => {
            resultDiv.innerHTML = `
                <div style="color: var(--success); padding: 1.5rem; border: 2px solid var(--success); border-radius: 8px; background: rgba(0,255,136,0.1);">
                    🎉 <strong>XSS Attack Successful!</strong><br><br>
                    <div style="background: rgba(0,0,0,0.5); padding: 1rem; border-radius: 8px; font-family: monospace;">
                        <div style="color: var(--secondary); margin-bottom: 0.5rem;">📡 Intercepted Cookie Data:</div>
                        <div style="color: var(--warning); font-size: 0.9rem;">
                            session_id=a8f9d2e4c6b8<br>
                            admin_session=secXplore{x55_c00k13_th13f_pr0}<br>
                            user_prefs=dark_theme<br>
                            tracking_id=7f8e9d2c3b1a
                        </div>
                    </div>
                    <div style="margin-top: 1rem; color: var(--primary);">
                        🏴 <strong>FLAG:</strong> <code style="background: var(--primary); color: var(--dark); padding: 0.3rem 0.6rem; border-radius: 4px;">secXplore{x55_c00k13_th13f_pr0}</code>
                    </div>
                </div>
            `;
        }, 3500);
    } else if (!blocked) {
        resultDiv.innerHTML = `
            <div style="color: var(--secondary); padding: 1rem; border: 1px solid var(--secondary); border-radius: 8px;">
                📝 Comment posted successfully!<br>
                <span style="font-size: 0.85rem; color: var(--gray);">💡 Tip: Try executing JavaScript that accesses document.cookie</span>
            </div>
        `;
    }
    
    commentInput.value = '';
};

// Cryptography - Multi-Layer Cipher
// ============================================
// CYBERCHEF LOGIC (Multi-Layer Cipher)
// ============================================
// ============================================
// CRYPTO 1: CYBERCHEF DECODER
// ============================================

// Recipe storage
let currentRecipe = [];

// Challenge encrypted data (Hex → ROT13 → Base64 of flag)
const CHALLENGE_DATA = '4a5449314e6b786c596e4a7a5a5664665a6d78685a31397a5a574e59634778766369686c';

// Load challenge data into input
window.loadChallenge = function() {
    document.getElementById('chefInput').value = CHALLENGE_DATA;
    document.getElementById('chefOutput').value = '';
};

// Drag and Drop Operations
window.dragOp = function(event) {
    event.dataTransfer.setData('operation', event.target.dataset.op);
    event.dataTransfer.setData('opName', event.target.textContent.trim());
};

window.allowDrop = function(event) {
    event.preventDefault();
    event.currentTarget.classList.add('drop-hover');
};

window.dropOp = function(event) {
    event.preventDefault();
    event.currentTarget.classList.remove('drop-hover');
    
    const opId = event.dataTransfer.getData('operation');
    const opName = event.dataTransfer.getData('opName');
    
    if (opId) {
        addToRecipe(opId, opName);
    }
};

// Add operation to recipe
function addToRecipe(opId, opName) {
    const recipeList = document.getElementById('recipeList');
    const placeholder = document.getElementById('recipePlaceholder');
    
    if (placeholder) {
        placeholder.style.display = 'none';
    }
    
    const recipeItem = document.createElement('div');
    recipeItem.className = 'recipe-item';
    recipeItem.dataset.op = opId;
    
    // Special handling for operations with parameters
    let paramHtml = '';
    if (opId === 'xor') {
        paramHtml = `
            <div class="op-params">
                <label>Key: <input type="text" class="op-param-input" data-param="key" value="0x00" style="width: 60px;"></label>
            </div>
        `;
    } else if (opId === 'caesar') {
        paramHtml = `
            <div class="op-params">
                <label>Shift: <input type="number" class="op-param-input" data-param="shift" value="13" min="1" max="25" style="width: 50px;"></label>
            </div>
        `;
    }
    
    recipeItem.innerHTML = `
        <div class="recipe-item-header">
            <span class="recipe-item-name">${opName}</span>
            <button class="recipe-item-remove" onclick="removeFromRecipe(this)">✕</button>
        </div>
        ${paramHtml}
    `;
    
    recipeList.appendChild(recipeItem);
    currentRecipe.push({ id: opId, name: opName });
}

// Remove operation from recipe
window.removeFromRecipe = function(btn) {
    const item = btn.closest('.recipe-item');
    const index = Array.from(item.parentNode.children).indexOf(item);
    
    item.remove();
    currentRecipe.splice(index, 1);
    
    // Show placeholder if empty
    if (currentRecipe.length === 0) {
        document.getElementById('recipePlaceholder').style.display = 'block';
    }
};

// Clear all recipe
window.clearRecipe = function() {
    document.getElementById('recipeList').innerHTML = '';
    document.getElementById('recipePlaceholder').style.display = 'block';
    document.getElementById('chefOutput').value = '';
    currentRecipe = [];
};

// BAKE - Execute recipe
window.bakeRecipe = function() {
    const input = document.getElementById('chefInput').value;
    const output = document.getElementById('chefOutput');
    const recipeItems = document.querySelectorAll('#recipeList .recipe-item');
    
    if (!input) {
        output.value = '⚠️ Please enter input data';
        return;
    }
    
    if (recipeItems.length === 0) {
        output.value = '⚠️ Please add operations to the recipe';
        return;
    }
    
    let result = input;
    let steps = [];
    
    try {
        recipeItems.forEach((item, index) => {
            const op = item.dataset.op;
            const prevResult = result;
            
            // Get parameters if any
            const params = {};
            item.querySelectorAll('.op-param-input').forEach(input => {
                params[input.dataset.param] = input.value;
            });
            
            result = executeOperation(op, result, params);
            steps.push(`Step ${index + 1} (${op}): ${result.substring(0, 50)}${result.length > 50 ? '...' : ''}`);
        });
        
        output.value = result;
        
        // Check if flag is found
        if (result.includes('secXplore{')) {
            output.style.color = 'var(--success)';
            output.value = result + '\n\n🎉 FLAG FOUND!';
        } else {
            output.style.color = 'var(--light)';
        }
        
    } catch (e) {
        output.value = `❌ Error: ${e.message}\n\nTry a different operation order.`;
        output.style.color = 'var(--danger)';
    }
};

// Execute single operation
function executeOperation(op, data, params = {}) {
    switch (op) {
        case 'base64decode':
            return atob(data);
            
        case 'base64encode':
            return btoa(data);
            
        case 'hexdecode':
            // Remove spaces and convert hex to string
            const hex = data.replace(/\s/g, '');
            let str = '';
            for (let i = 0; i < hex.length; i += 2) {
                str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
            }
            return str;
            
        case 'hexencode':
            let hexResult = '';
            for (let i = 0; i < data.length; i++) {
                hexResult += data.charCodeAt(i).toString(16).padStart(2, '0');
            }
            return hexResult;
            
        case 'rot13':
            return data.replace(/[a-zA-Z]/g, function(c) {
                return String.fromCharCode(
                    (c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
                );
            });
            
        case 'rot47':
            return data.replace(/[!-~]/g, function(c) {
                return String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94));
            });
            
        case 'reverse':
            return data.split('').reverse().join('');
            
        case 'xor':
            const key = parseInt(params.key) || 0;
            return data.split('').map(c => 
                String.fromCharCode(c.charCodeAt(0) ^ key)
            ).join('');
            
        case 'caesar':
            const shift = parseInt(params.shift) || 13;
            return data.replace(/[a-zA-Z]/g, function(c) {
                const base = c <= 'Z' ? 65 : 97;
                return String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base);
            });
            
        case 'atbash':
            return data.replace(/[a-zA-Z]/g, function(c) {
                const base = c <= 'Z' ? 65 : 97;
                return String.fromCharCode(base + (25 - (c.charCodeAt(0) - base)));
            });
            
        case 'urldecode':
            return decodeURIComponent(data);
            
        case 'urlencode':
            return encodeURIComponent(data);
            
        case 'lowercase':
            return data.toLowerCase();
            
        case 'uppercase':
            return data.toUpperCase();
            
        case 'removewhitespace':
            return data.replace(/\s/g, '');
            
        default:
            return data;
    }
}

// Filter operations by search
window.filterOperations = function(query) {
    const items = document.querySelectorAll('.op-item');
    const lowerQuery = query.toLowerCase();
    
    items.forEach(item => {
        const text = item.textContent.toLowerCase();
        if (text.includes(lowerQuery) || !query) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
};

// Copy output to clipboard
window.copyOutput = function() {
    const output = document.getElementById('chefOutput');
    output.select();
    document.execCommand('copy');
    
    // Show feedback
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => btn.textContent = originalText, 1500);
};

// Auto-load challenge on page load
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('chefInput')) {
        loadChallenge();
    }
});

// Cryptography - XOR Brute Force

window.xorDecrypt = function() {
    const keyInput = document.getElementById('xorKey').value.trim();
    const hexInput = document.getElementById('xorInput').value.trim();
    const output = document.getElementById('xorOutput');
    
    if (!keyInput || !hexInput) {
        output.innerHTML = '<span style="color: var(--warning);">⚠️ Please enter key and hex input</span>';
        return;
    }
    
    // Parse key (support both decimal and hex)
    let key;
    if (keyInput.startsWith('0x')) {
        key = parseInt(keyInput, 16);
    } else {
        key = parseInt(keyInput);
    }
    
    if (isNaN(key) || key < 0 || key > 255) {
        output.innerHTML = '<span style="color: var(--danger);">❌ Invalid key (must be 0-255)</span>';
        return;
    }
    
    // Parse hex bytes
    const hexBytes = hexInput.split(/\s+/).filter(b => b.length > 0);
    const decrypted = hexBytes.map(b => {
        const byte = parseInt(b, 16);
        return String.fromCharCode(byte ^ key);
    }).join('');
    
    const isFlag = decrypted.includes('secXplore{');
    
    output.innerHTML = `
        <div style="color: var(--secondary);">🔑 Key: ${key} (0x${key.toString(16).padStart(2, '0')})</div>
        <div style="color: var(--gray); margin: 0.5rem 0;">📝 Result:</div>
        <code style="color: ${isFlag ? 'var(--success)' : 'var(--light)'}; word-break: break-all; font-size: ${isFlag ? '1.1rem' : '0.9rem'};">${escapeHtml(decrypted)}</code>
        ${isFlag ? '<div style="color: var(--success); margin-top: 1rem;">🎉 FLAG FOUND!</div>' : ''}
    `;
};

window.xorBruteForce = function() {
    const hexInput = document.getElementById('xorInput').value.trim();
    const output = document.getElementById('xorOutput');
    
    if (!hexInput) {
        output.innerHTML = '<span style="color: var(--warning);">⚠️ Please enter hex input</span>';
        return;
    }
    
    const hexBytes = hexInput.split(/\s+/).filter(b => b.length > 0);
    
    output.innerHTML = '<div style="color: var(--secondary);">🔨 Brute forcing all 256 keys...</div>\n';
    
    let results = [];
    
    for (let key = 0; key < 256; key++) {
        const decrypted = hexBytes.map(b => {
            const byte = parseInt(b, 16);
            return String.fromCharCode(byte ^ key);
        }).join('');
        
        // Check for readable output
        const isPrintable = /^[\x20-\x7E]+$/.test(decrypted);
        const hasFlag = decrypted.includes('secXplore{') || decrypted.includes('CTF{') || decrypted.includes('flag{');
        
        if (hasFlag) {
            results.unshift({key, decrypted, priority: 1});
        } else if (isPrintable && decrypted.length > 5) {
            results.push({key, decrypted, priority: 2});
        }
    }
    
    // Show results
    output.innerHTML += `<div style="color: var(--gray); margin: 0.5rem 0;">Found ${results.length} potential matches:</div>\n`;
    
    results.slice(0, 15).forEach(r => {
        const isFlag = r.priority === 1;
        output.innerHTML += `
            <div style="padding: 0.5rem; margin: 0.3rem 0; background: rgba(${isFlag ? '0,255,136' : '0,0,0'},0.${isFlag ? '2' : '3'}); border-radius: 4px; border-left: 3px solid ${isFlag ? 'var(--success)' : 'var(--gray)'};">
                <span style="color: var(--secondary);">Key ${r.key} (0x${r.key.toString(16).padStart(2, '0')}):</span>
                <code style="color: ${isFlag ? 'var(--success)' : 'var(--light)'}; margin-left: 0.5rem;">${escapeHtml(r.decrypted)}</code>
                ${isFlag ? ' 🎉 FLAG!' : ''}
            </div>
        `;
    });
    
    if (results.length === 0) {
        output.innerHTML += '<div style="color: var(--warning);">No readable results found</div>';
    }
};
// Cryptography - RSA Small Exponent Attack
window.rsaShowCRT = function() {
    const output = document.getElementById('rsaOutput');
    output.innerHTML = `<span style="color: var(--secondary);">📐 Chinese Remainder Theorem (CRT) Formula:</span>

<span style="color: var(--gray);">Given:</span>
  e = 3 (public exponent)
  c1 ≡ m³ (mod n1)
  c2 ≡ m³ (mod n2)  
  c3 ≡ m³ (mod n3)

<span style="color: var(--gray);">CRT Solution:</span>
  N = n1 × n2 × n3
  N1 = N/n1, N2 = N/n2, N3 = N/n3
  
  Find y1, y2, y3 where:
    N1 × y1 ≡ 1 (mod n1)
    N2 × y2 ≡ 1 (mod n2)
    N3 × y3 ≡ 1 (mod n3)
  
  <span style="color: var(--primary);">m³ = (c1×N1×y1 + c2×N2×y2 + c3×N3×y3) mod N</span>

<span style="color: var(--warning);">Then compute: m = ∛(m³)</span>
`;
};

window.rsaCalculateCRT = function() {
    const output = document.getElementById('rsaOutput');
    output.innerHTML = `<span style="color: var(--secondary);">🔢 Calculating m³ using CRT...</span>

<span style="color: var(--gray);">Step 1: Calculate N = n1 × n2 × n3</span>
N = 95642412847883940786305809307353693569 × 
    117459929787100018763388685239228564389 × 
    122656808337815211204693407655668838229

<span style="color: var(--primary);">N ≈ 1.378 × 10^114</span>

<span style="color: var(--gray);">Step 2: Calculate N1, N2, N3</span>
N1 = N / n1
N2 = N / n2
N3 = N / n3

<span style="color: var(--gray);">Step 3: Find modular inverses y1, y2, y3</span>
Using Extended Euclidean Algorithm...

<span style="color: var(--gray);">Step 4: Combine results</span>
<span style="color: var(--success);">m³ = 3684829473827492837492837492837482934792837492837</span>

<span style="color: var(--warning);">Now calculate the cube root! Click "∛ Cube Root"</span>
`;
};

window.rsaCubeRoot = function() {
    const output = document.getElementById('rsaOutput');
    output.innerHTML = `<span style="color: var(--secondary);">∛ Calculating Cube Root of m³...</span>

<span style="color: var(--gray);">m³ = 3684829473827492837492837492837482934792837492837</span>

<span style="color: var(--gray);">Using Newton's method for integer cube root:</span>

<span style="color: var(--primary);">m = 154283749172849172</span>

<span style="color: var(--gray);">Converting to bytes...</span>

<span style="color: var(--warning);">Click "📝 To ASCII" to see the plaintext!</span>
`;
};

window.rsaToBytes = function() {
    const output = document.getElementById('rsaOutput');
    output.innerHTML = `<span style="color: var(--secondary);">📝 Converting m to ASCII text...</span>

<span style="color: var(--gray);">m (decimal) = 154283749172849172</span>
<span style="color: var(--gray);">m (hex) = 0x7365635870...</span>

<span style="color: var(--gray);">Byte array: [115, 101, 99, 88, 112, 108, 111, 114, 101, ...]</span>

<span style="color: var(--success);">ASCII: secXplore{h4st4ds_br04dc4st_4tt4ck}</span>

<span style="color: var(--primary);">🎉 FLAG: secXplore{h4st4ds_br04dc4st_4tt4ck}</span>
`;
};

window.rsaSolveAll = function() {
    const output = document.getElementById('rsaOutput');
    
    output.innerHTML = `<span style="color: var(--secondary);">🚀 Running complete Håstad's Broadcast Attack...</span>\n`;
    
    setTimeout(() => {
        output.innerHTML += `\n<span style="color: var(--gray);">[1/4] Calculating N = n1 × n2 × n3...</span>`;
    }, 500);
    
    setTimeout(() => {
        output.innerHTML += `<span style="color: var(--success);"> ✓</span>\n<span style="color: var(--gray);">[2/4] Computing CRT to find m³...</span>`;
    }, 1200);
    
    setTimeout(() => {
        output.innerHTML += `<span style="color: var(--success);"> ✓</span>\n<span style="color: var(--gray);">[3/4] Calculating integer cube root...</span>`;
    }, 2000);
    
    setTimeout(() => {
        output.innerHTML += `<span style="color: var(--success);"> ✓</span>\n<span style="color: var(--gray);">[4/4] Converting to ASCII...</span>`;
    }, 2800);
    
    setTimeout(() => {
        output.innerHTML += `<span style="color: var(--success);"> ✓</span>

<div style="margin-top: 1rem; padding: 1rem; background: rgba(0,255,136,0.1); border: 1px solid var(--success); border-radius: 8px;">
    <div style="color: var(--success); font-size: 1.1rem; margin-bottom: 0.5rem;">🎉 Attack Successful!</div>
    <div style="color: var(--gray);">Recovered plaintext:</div>
    <code style="color: var(--primary); font-size: 1.1rem;">secXplore{h4st4ds_br04dc4st_4tt4ck}</code>
</div>
`;
    }, 3500);
};

// Forensics - Birthday EXIF Data
window.executeBirthdayCommand = function() {
    const input = document.getElementById('birthdayCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('birthdayTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  exiftool [file]              - View all EXIF metadata
  exiftool -[tag] [file]       - View specific tag
  exiftool -a -u [file]        - View all tags (verbose)
  file [file]                  - File type information
  strings [file]               - Extract strings
  xxd [file] | head            - Hex dump
  identify -verbose [file]     - ImageMagick info
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           EXIF METADATA ANALYZER                             │
│           Digital Forensics Workstation                      │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">Evidence file loaded: birthday_photo.jpg</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // FILE
    else if (cmd.includes('file ')) {
        terminal.innerHTML += `<span style="color: #8b949e;">birthday_photo.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=11], baseline, precision 8, 4032x3024, components 3</span>\n`;
    }
    // EXIFTOOL (full)
    else if (cmd.includes('exiftool') && cmd.includes('birthday') && !cmd.includes('-')) {
        terminal.innerHTML += `<span style="color: #8b949e;">ExifTool Version Number         : 12.42
File Name                       : birthday_photo.jpg
File Size                       : 2.4 MB
File Type                       : JPEG
MIME Type                       : image/jpeg
Image Width                     : 4032
Image Height                    : 3024
Camera Model Name               : iPhone 14 Pro
Date/Time Original              : 2024:03:15 14:30:25
Create Date                     : 2024:03:15 14:30:25
Modify Date                     : 2024:03:15 14:30:25
Artist                          : John Smith
Copyright                       : 2024 Birthday Party
GPS Latitude                    : 40 deg 42' 46.08" N
GPS Longitude                   : 74 deg 0' 21.60" W
<span style="color: #ffa657;">User Comment                    : secXplore{3x1f_m3t4d4t4_h1dd3n}</span>
<span style="color: #ffa657;">Comment                         : Happy Birthday! The flag is in User Comment</span>
Flash                           : No Flash
Focal Length                    : 6.9 mm
ISO                             : 64
</span>`;
    }
    // EXIFTOOL specific tags
    else if (cmd.includes('exiftool') && (cmd.includes('-comment') || cmd.includes('-usercomment') || cmd.includes('-a'))) {
        terminal.innerHTML += `<span style="color: #8b949e;">Comment                         : Happy Birthday! The flag is in User Comment
<span style="color: #7ee787;">User Comment                    : secXplore{3x1f_m3t4d4t4_h1dd3n}</span>
</span>`;
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        if (cmd.includes('grep') || cmd.includes('flag') || cmd.includes('sec')) {
            terminal.innerHTML += `<span style="color: #7ee787;">secXplore{3x1f_m3t4d4t4_h1dd3n}</span>\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">JFIF
Exif
iPhone 14 Pro
2024:03:15 14:30:25
John Smith
Happy Birthday! The flag is in User Comment
secXplore{3x1f_m3t4d4t4_h1dd3n}
...
</span>`;
        }
    }
    // XXD
    else if (cmd.includes('xxd')) {
        terminal.innerHTML += `<span style="color: #8b949e;">00000000: ffd8 ffe0 0010 4a46 4946 0001 0101 0048  ......JFIF.....H
00000010: 0048 0000 ffe1 1c48 4578 6966 0000 4d4d  .H.....HExif..MM
00000020: 002a 0000 0008 000b 010f 0002 0000 0020  .*............. 
00000030: 0000 009a 0110 0002 0000 000e 0000 00ba  ................
</span>`;
    }
    // IDENTIFY
    else if (cmd.includes('identify')) {
        terminal.innerHTML += `<span style="color: #8b949e;">birthday_photo.jpg JPEG 4032x3024 4032x3024+0+0 8-bit sRGB 2.4MB 0.000u 0:00.000
  Properties:
    exif:Artist: John Smith
    exif:UserComment: secXplore{3x1f_m3t4d4t4_h1dd3n}
</span>`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};

// Forensics - Geolocation Tracker

window.executeGeoCommand = function() {
    const input = document.getElementById('geoCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('geoTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  exiftool [file]              - View all metadata
  exiftool -GPS* [file]        - GPS data only
  exiftool -n -GPS* [file]     - GPS in decimal format
  exiftool -c "%.6f" [file]    - GPS coordinates formatted
  file [file]                  - File type info
  strings [file]               - Extract strings
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           GEOLOCATION FORENSICS TOOL                         │
│           GPS Coordinate Extractor                           │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">Evidence file loaded: mystery_location.jpg</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // EXIFTOOL GPS
    else if (cmd.includes('exiftool') && cmd.includes('-gps')) {
        if (cmd.includes('-n')) {
            terminal.innerHTML += `<span style="color: #8b949e;">GPS Latitude                    : 48.8583701
GPS Longitude                   : 2.2944813
GPS Altitude                    : 35.2
GPS Position                    : <span style="color: #ffa657;">48.8583701, 2.2944813</span>
</span>
<span style="color: #7ee787;">💡 Tip: Search these coordinates on Google Maps!</span>
`;
        } else if (cmd.includes('-c')) {
            terminal.innerHTML += `<span style="color: #8b949e;">GPS Latitude                    : 48.858370
GPS Longitude                   : 2.294481
GPS Position                    : <span style="color: #ffa657;">48.858370, 2.294481</span>
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">GPS Latitude                    : 48 deg 51' 30.13" N
GPS Longitude                   : 2 deg 17' 40.13" E
GPS Altitude                    : 35.2 m Above Sea Level
GPS Position                    : <span style="color: #ffa657;">48 deg 51' 30.13" N, 2 deg 17' 40.13" E</span>
</span>
<span style="color: #7ee787;">💡 Hint: Use -n flag for decimal coordinates</span>
`;
        }
    }
    // EXIFTOOL full
    else if (cmd.includes('exiftool') && cmd.includes('mystery')) {
        terminal.innerHTML += `<span style="color: #8b949e;">ExifTool Version Number         : 12.42
File Name                       : mystery_location.jpg
File Size                       : 1.8 MB
File Type                       : JPEG
Camera Model Name               : Canon EOS R5
Date/Time Original              : 2024:01:20 15:45:30
<span style="color: #ffa657;">GPS Latitude                    : 48 deg 51' 30.13" N</span>
<span style="color: #ffa657;">GPS Longitude                   : 2 deg 17' 40.13" E</span>
GPS Altitude                    : 35.2 m Above Sea Level
Comment                         : What famous landmark is this?
</span>
<span style="color: #7ee787;">💡 These coordinates point to a famous landmark in Paris!</span>
`;
    }
    // FILE
    else if (cmd.includes('file ')) {
        terminal.innerHTML += `<span style="color: #8b949e;">mystery_location.jpg: JPEG image data, JFIF standard 1.01, Exif Standard</span>\n`;
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        terminal.innerHTML += `<span style="color: #8b949e;">JFIF
Canon EOS R5
2024:01:20 15:45:30
GPS coordinates: 48.8583701, 2.2944813
What famous landmark is this?
Flag format: secXplore{landmark_name}
</span>`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};

// Steganography
window.executeStegoCommand = function() {
    const input = document.getElementById('stegoCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('stegoTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  binwalk [file]               - Scan for embedded files
  binwalk -e [file]            - Extract embedded files
  strings [file]               - Extract printable strings
  zsteg [file]                 - LSB steganography analysis
  steghide extract -sf [file]  - Extract hidden data
  xxd [file] | head            - Hex dump
  file [file]                  - File type info
  unzip [file]                 - Extract ZIP archive
  base64 -d                    - Decode base64
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           STEGANOGRAPHY ANALYSIS SUITE                       │
│           Hidden Data Extraction Tool                        │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">Evidence file loaded: innocent_image.png</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // FILE
    else if (cmd.includes('file ') && cmd.includes('innocent')) {
        terminal.innerHTML += `<span style="color: #8b949e;">innocent_image.png: PNG image data, 1920 x 1080, 8-bit/color RGBA, non-interlaced</span>\n`;
    }
    // BINWALK scan
    else if (cmd.includes('binwalk') && !cmd.includes('-e')) {
        terminal.innerHTML += `<span style="color: #8b949e;">
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1920 x 1080, 8-bit/color RGBA
91            0x5B            Zlib compressed data, default compression
847293        0xCEE3D         <span style="color: #ffa657;">Zip archive data, encrypted at least v2.0 to extract</span>
847524        0xCEF24         End of Zip archive, footer length: 22

<span style="color: #7ee787;">📦 Found hidden ZIP archive at offset 847293!</span>
</span>`;
    }
    // BINWALK extract
    else if (cmd.includes('binwalk -e') || cmd.includes('binwalk --extract')) {
        terminal.innerHTML += `<span style="color: #8b949e;">
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1920 x 1080, 8-bit/color RGBA
847293        0xCEE3D         Zip archive data, encrypted

Extracted files:
  _innocent_image.png.extracted/
    └── CEE3D.zip (password protected)

<span style="color: #ffa657;">⚠️ ZIP file is password protected!</span>
<span style="color: #7ee787;">💡 Hint: Password might be hidden in the image... try "whiteflag"</span>
</span>`;
    }
    // UNZIP with wrong password
    else if (cmd.includes('unzip') && !cmd.includes('whiteflag') && !cmd.includes('-P whiteflag')) {
        terminal.innerHTML += `<span style="color: #8b949e;">Archive:  hidden.zip
   creating: secret/
[hidden.zip] secret/flag.txt password: 
<span style="color: #f97583;">password incorrect--reenter: 
   skipping: secret/flag.txt         incorrect password</span>

<span style="color: #7ee787;">💡 Hint: Look for password in the image. Try "whiteflag"</span>
</span>`;
    }
    // UNZIP with correct password
    else if (cmd.includes('unzip') && (cmd.includes('whiteflag') || cmd.includes('-P whiteflag'))) {
        terminal.innerHTML += `<span style="color: #8b949e;">Archive:  hidden.zip
[hidden.zip] secret/flag.txt password: 
  inflating: secret/flag.txt

<span style="color: #7ee787;">✅ Extraction successful!</span>

Contents of secret/flag.txt:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
c2VjWHBsb3Jle3N0M2cwX2gxZGQzbl9kNHQ0fQ==

<span style="color: #ffa657;">💡 This looks like Base64! Try: echo "..." | base64 -d</span>
</span>`;
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        if (cmd.includes('grep') && (cmd.includes('pass') || cmd.includes('flag'))) {
            terminal.innerHTML += `<span style="color: #8b949e;">password: whiteflag
secret_flag_location
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">PNG
IHDR
IDAT
tEXt
Software: Adobe Photoshop
<span style="color: #ffa657;">password: whiteflag</span>
secret_flag_location
PK (ZIP signature)
</span>`;
        }
    }
    // ZSTEG
    else if (cmd.includes('zsteg')) {
        terminal.innerHTML += `<span style="color: #8b949e;">imagedata           .. text: "whiteflag"
b1,r,lsb,xy         .. text: "password hint inside"
b1,rgb,lsb,xy       .. file: PK Zip archive data
</span>`;
    }
    // BASE64 decode
    else if (cmd.includes('base64') && cmd.includes('-d')) {
        if (cmd.includes('c2VjWHBsb3Jle3N0M2cwX2gxZGQzbl9kNHQ0fQ==')) {
            terminal.innerHTML += `<span style="color: #7ee787;">secXplore{st3g0_h1dd3n_d4t4}</span>\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: echo "base64string" | base64 -d</span>\n`;
        }
    }
    // ECHO with base64
    else if (cmd.includes('echo') && cmd.includes('base64')) {
        if (cmd.includes('c2VjWHBsb3Jle3N0M2cwX2gxZGQzbl9kNHQ0fQ==')) {
            terminal.innerHTML += `<span style="color: #7ee787;">secXplore{st3g0_h1dd3n_d4t4}</span>\n`;
        }
    }
    // XXD
    else if (cmd.includes('xxd')) {
        terminal.innerHTML += `<span style="color: #8b949e;">00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0780 0000 0438 0806 0000 00c5 7d66  .......8......}f
00000020: 8900 0000 0473 5247 4200 aece 1ce9 0000  .....sRGB.......
...
000cee30: 504b 0304 1400 0900 0800 0000 0000 0000  PK..............
</span>`;
    }
    // STEGHIDE
    else if (cmd.includes('steghide')) {
        terminal.innerHTML += `<span style="color: #8b949e;">Enter passphrase: 
wrote extracted data to "flag.txt".

<span style="color: #7ee787;">Contents: c2VjWHBsb3Jle3N0M2cwX2gxZGQzbl9kNHQ0fQ==</span>
</span>`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};

// Network
// NETWORK 1: PACKET SNIFFER BASIC
// ============================================
window.executePacketCommand = function() {
    const input = document.getElementById('packetCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('packetTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  tcpdump -r [file]                    - Read pcap file
  tcpdump -r [file] -A                 - Show ASCII content
  tcpdump -r [file] -X                 - Show hex + ASCII
  tshark -r [file]                     - Detailed packet view
  tshark -r [file] -Y "filter"         - Apply display filter
  tshark -r [file] -T fields -e field  - Extract specific fields
  capinfos [file]                      - Capture file info
  strings [file]                       - Extract strings
  clear                                - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           PACKET ANALYSIS WORKSTATION                        │
│           Network Traffic Analyzer                           │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">Capture file loaded: network_capture.pcap</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // CAPINFOS
    else if (cmd.includes('capinfos')) {
        terminal.innerHTML += `<span style="color: #8b949e;">File name:           network_capture.pcap
File type:           Wireshark/tcpdump - pcap
File encapsulation:  Ethernet
Number of packets:   156
File size:           45.2 kB
Capture duration:    32.5 seconds
First packet time:   2024-01-15 10:30:15
Last packet time:    2024-01-15 10:30:47
</span>`;
    }
    // TCPDUMP basic
    else if (cmd.includes('tcpdump -r') && !cmd.includes('-a') && !cmd.includes('-x')) {
        terminal.innerHTML += `<span style="color: #8b949e;">reading from file network_capture.pcap, link-type EN10MB (Ethernet)
10:30:15.123456 IP 192.168.1.100.54321 > 192.168.1.50.80: Flags [S], seq 1234567
10:30:15.123789 IP 192.168.1.50.80 > 192.168.1.100.54321: Flags [S.], seq 7654321
10:30:15.124012 IP 192.168.1.100.54321 > 192.168.1.50.80: Flags [.], ack 1
10:30:15.125234 IP 192.168.1.100.54321 > 192.168.1.50.80: Flags [P.], HTTP GET /login
10:30:15.234567 IP 192.168.1.100.54321 > 192.168.1.50.80: Flags [P.], <span style="color: #ffa657;">HTTP POST /login</span>
...
<span style="color: #7ee787;">💡 Tip: Use -A flag to see packet contents, or filter for HTTP POST</span>
</span>`;
    }
    // TCPDUMP with -A
    else if (cmd.includes('tcpdump') && cmd.includes('-a')) {
        terminal.innerHTML += `<span style="color: #8b949e;">10:30:15.234567 IP 192.168.1.100.54321 > 192.168.1.50.80: Flags [P.]
E..{..@.@.....d...2.P.......POST /login HTTP/1.1
Host: 192.168.1.50
Content-Type: application/x-www-form-urlencoded
Content-Length: 52

<span style="color: #ffa657;">username=admin&password=secXplore{p4ck3t_sn1ff3r_pr0}</span>
</span>`;
    }
    // TSHARK HTTP filter
    else if (cmd.includes('tshark') && cmd.includes('http')) {
        if (cmd.includes('post')) {
            terminal.innerHTML += `<span style="color: #8b949e;">   15   0.234567 192.168.1.100 → 192.168.1.50 HTTP POST /login HTTP/1.1
<span style="color: #ffa657;">Frame contains: username=admin&password=secXplore{p4ck3t_sn1ff3r_pr0}</span>
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">    5   0.125234 192.168.1.100 → 192.168.1.50 HTTP GET /login HTTP/1.1
    8   0.156789 192.168.1.50 → 192.168.1.100 HTTP 200 OK
   15   0.234567 192.168.1.100 → 192.168.1.50 <span style="color: #ffa657;">HTTP POST /login HTTP/1.1</span>
   18   0.267890 192.168.1.50 → 192.168.1.100 HTTP 302 Found

<span style="color: #7ee787;">💡 Tip: Filter POST requests: -Y "http.request.method == POST"</span>
</span>`;
        }
    }
    // TSHARK extract fields
    else if (cmd.includes('tshark') && cmd.includes('-t fields') && cmd.includes('http.file_data')) {
        terminal.innerHTML += `<span style="color: #7ee787;">username=admin&password=secXplore{p4ck3t_sn1ff3r_pr0}</span>\n`;
    }
    // TSHARK basic
    else if (cmd.includes('tshark -r')) {
        terminal.innerHTML += `<span style="color: #8b949e;">    1   0.000000 192.168.1.100 → 192.168.1.50 TCP 54321 → 80 [SYN]
    2   0.000333 192.168.1.50 → 192.168.1.100 TCP 80 → 54321 [SYN, ACK]
    3   0.000456 192.168.1.100 → 192.168.1.50 TCP 54321 → 80 [ACK]
    4   0.001234 192.168.1.100 → 192.168.1.50 HTTP GET /
    5   0.125234 192.168.1.100 → 192.168.1.50 HTTP GET /login
   ...
   15   0.234567 192.168.1.100 → 192.168.1.50 <span style="color: #ffa657;">HTTP POST /login</span>
   ...

<span style="color: #7ee787;">💡 Filter HTTP: -Y "http"</span>
</span>`;
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        if (cmd.includes('password') || cmd.includes('pass') || cmd.includes('flag')) {
            terminal.innerHTML += `<span style="color: #7ee787;">password=secXplore{p4ck3t_sn1ff3r_pr0}</span>\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">GET /login HTTP/1.1
Host: 192.168.1.50
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded
username=admin
<span style="color: #ffa657;">password=secXplore{p4ck3t_sn1ff3r_pr0}</span>
HTTP/1.1 302 Found
</span>`;
        }
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};

// DNS Tunneling Command Executor
window.executeDNSCommand = function() {
    const input = document.getElementById('dnsCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('dnsTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  tshark -r [file] -Y "dns"            - Filter DNS traffic
  tshark -r [file] -Y "dns" -T fields -e dns.qry.name
                                       - Extract query names
  tcpdump -r [file] -n port 53         - DNS traffic
  dig [domain]                         - DNS lookup
  strings [file]                       - Extract strings
  echo "text" | base64 -d              - Decode Base64
  clear                                - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           DNS TRAFFIC ANALYZER                               │
│           Data Exfiltration Detection                        │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #f97583;">⚠ Suspicious DNS activity detected!</span>
<span style="color: #8b949e;">Capture file loaded: dns_traffic.pcap</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // TSHARK DNS basic
    else if (cmd.includes('tshark') && cmd.includes('dns') && !cmd.includes('exfil') && !cmd.includes('-t fields')) {
        terminal.innerHTML += `<span style="color: #8b949e;">    3   0.002222 192.168.1.105 → 8.8.8.8 DNS Standard query A google.com
    4   0.003333 8.8.8.8 → 192.168.1.105 DNS Standard query response A 142.250.x.x
   15   1.234567 192.168.1.105 → 8.8.8.8 DNS Standard query A <span style="color: #ffa657;">c2VjWHBsb3Jl.exfil.malicious.com</span>
   28   2.345678 192.168.1.105 → 8.8.8.8 DNS Standard query A <span style="color: #ffa657;">e2RuczFfdHVu.exfil.malicious.com</span>
   41   3.456789 192.168.1.105 → 8.8.8.8 DNS Standard query A <span style="color: #ffa657;">bjNsXzN4ZjFs.exfil.malicious.com</span>
   54   4.567890 192.168.1.105 → 8.8.8.8 DNS Standard query A <span style="color: #ffa657;">dHI0dDEwbn0=.exfil.malicious.com</span>

<span style="color: #f97583;">⚠ Suspicious queries to exfil.malicious.com detected!</span>
<span style="color: #7ee787;">💡 Tip: Extract the subdomains and combine them</span>
</span>`;
    }
    // TSHARK DNS with exfil filter
    else if (cmd.includes('tshark') && cmd.includes('exfil') && cmd.includes('-t fields')) {
        terminal.innerHTML += `<span style="color: #ffa657;">c2VjWHBsb3Jl.exfil.malicious.com
e2RuczFfdHVu.exfil.malicious.com
bjNsXzN4ZjFs.exfil.malicious.com
dHI0dDEwbn0=.exfil.malicious.com</span>

<span style="color: #7ee787;">📝 Subdomains (Base64 encoded data):
c2VjWHBsb3Jl + e2RuczFfdHVu + bjNsXzN4ZjFs + dHI0dDEwbn0=

💡 Combine and decode: echo "c2VjWHBsb3Jle2RuczFfdHVubjNsXzN4ZjFsdHI0dDEwbn0=" | base64 -d</span>
`;
    }
    // TSHARK DNS with exfil (no fields)
    else if (cmd.includes('tshark') && cmd.includes('exfil')) {
        terminal.innerHTML += `<span style="color: #8b949e;">   15   1.234567 192.168.1.105 → 8.8.8.8 DNS A c2VjWHBsb3Jl.exfil.malicious.com
   28   2.345678 192.168.1.105 → 8.8.8.8 DNS A e2RuczFfdHVu.exfil.malicious.com
   41   3.456789 192.168.1.105 → 8.8.8.8 DNS A bjNsXzN4ZjFs.exfil.malicious.com
   54   4.567890 192.168.1.105 → 8.8.8.8 DNS A dHI0dDEwbn0=.exfil.malicious.com

<span style="color: #7ee787;">💡 Add -T fields -e dns.qry.name to extract query names only</span>
</span>`;
    }
    // BASE64 decode
    else if (cmd.includes('base64') && cmd.includes('-d')) {
        if (cmd.includes('c2VjWHBsb3Jle2RuczFfdHVubjNsXzN4ZjFsdHI0dDEwbn0=')) {
            terminal.innerHTML += `<span style="color: #7ee787;">secXplore{dns1_tunn3l_3xf1ltr4t10n}</span>\n`;
        } else if (cmd.includes('c2VjWHBsb3Jl')) {
            terminal.innerHTML += `<span style="color: #8b949e;">secXplore</span>
<span style="color: #7ee787;">💡 This is just part of the data. Combine all subdomains!</span>
`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: echo "base64_string" | base64 -d</span>\n`;
        }
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        terminal.innerHTML += `<span style="color: #8b949e;">google.com
c2VjWHBsb3Jl.exfil.malicious.com
e2RuczFfdHVu.exfil.malicious.com
bjNsXzN4ZjFs.exfil.malicious.com
dHI0dDEwbn0=.exfil.malicious.com
</span>`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};
// NETWORK 3: ARP SPOOFING
// ============================================
window.executeArpCommand = function() {
    const input = document.getElementById('arpCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('arpTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  tshark -r [file] -Y "arp"            - Filter ARP traffic
  tshark -r [file] -Y "arp.opcode == 2" - ARP replies only
  tshark -r [file] -T fields -e eth.src -e arp.src.proto_ipv4
                                       - Extract MAC-IP mappings
  tcpdump -r [file] arp                - ARP packets
  arp -a                               - Show ARP table
  strings [file] | grep -i flag        - Search for flag
  clear                                - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           ARP ATTACK FORENSICS                               │
│           Man-in-the-Middle Detection                        │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #f97583;">⚠ ALERT: ARP spoofing detected in capture!</span>
<span style="color: #8b949e;">Capture file loaded: arp_attack.pcap</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // TSHARK ARP basic
    else if (cmd.includes('tshark') && cmd.includes('arp') && !cmd.includes('opcode') && !cmd.includes('-t fields')) {
        terminal.innerHTML += `<span style="color: #8b949e;">    1   0.000000 aa:bb:cc:dd:ee:01 → Broadcast ARP Who has 192.168.1.1? Tell 192.168.1.100
    2   0.000234 <span style="color: #7ee787;">aa:bb:cc:dd:ee:ff</span> → aa:bb:cc:dd:ee:01 ARP 192.168.1.1 is at aa:bb:cc:dd:ee:ff
    5   1.000000 <span style="color: #f97583;">aa:bb:cc:11:22:33</span> → Broadcast ARP 192.168.1.1 is at <span style="color: #f97583;">aa:bb:cc:11:22:33</span>
    6   1.000123 <span style="color: #f97583;">aa:bb:cc:11:22:33</span> → Broadcast ARP 192.168.1.254 is at <span style="color: #f97583;">aa:bb:cc:11:22:33</span>
   12   2.000000 <span style="color: #f97583;">aa:bb:cc:11:22:33</span> → Broadcast ARP 192.168.1.1 is at <span style="color: #f97583;">aa:bb:cc:11:22:33</span>

<span style="color: #f97583;">⚠ SUSPICIOUS: MAC aa:bb:cc:11:22:33 claiming multiple IPs!</span>
<span style="color: #7ee787;">💡 This is the attacker's MAC address</span>
</span>`;
    }
    // TSHARK ARP replies
    else if (cmd.includes('tshark') && cmd.includes('opcode')) {
        terminal.innerHTML += `<span style="color: #8b949e;">    2   0.000234 aa:bb:cc:dd:ee:ff → aa:bb:cc:dd:ee:01 ARP 192.168.1.1 is at aa:bb:cc:dd:ee:ff
    5   1.000000 <span style="color: #f97583;">aa:bb:cc:11:22:33 → Broadcast ARP 192.168.1.1 is at aa:bb:cc:11:22:33</span>
    6   1.000123 <span style="color: #f97583;">aa:bb:cc:11:22:33 → Broadcast ARP 192.168.1.254 is at aa:bb:cc:11:22:33</span>

<span style="color: #f97583;">⚠ Gratuitous ARP detected - classic ARP spoofing pattern!</span>
<span style="color: #7ee787;">Attacker MAC: aa:bb:cc:11:22:33</span>
</span>`;
    }
    // TSHARK extract fields
    else if (cmd.includes('tshark') && cmd.includes('-t fields')) {
        terminal.innerHTML += `<span style="color: #8b949e;">aa:bb:cc:dd:ee:01    192.168.1.100
aa:bb:cc:dd:ee:ff    192.168.1.1
<span style="color: #f97583;">aa:bb:cc:11:22:33    192.168.1.1</span>      ← DUPLICATE!
<span style="color: #f97583;">aa:bb:cc:11:22:33    192.168.1.254</span>    ← ATTACKER!

<span style="color: #7ee787;">Attacker MAC: aa:bb:cc:11:22:33 (claiming gateway IPs)</span>
</span>`;
    }
    // TSHARK HTTP from attacker
    else if (cmd.includes('tshark') && cmd.includes('http') && cmd.includes('aa:bb:cc:11:22:33')) {
        terminal.innerHTML += `<span style="color: #8b949e;">Intercepted traffic from attacker:

Frame 89: HTTP POST /login
  <span style="color: #ffa657;">username=victim&password=secXplore{4rp_sp00f_m1tm_4tt4ck}</span>

<span style="color: #7ee787;">🎉 Found the stolen credentials!</span>
</span>`;
    }
    // TSHARK HTTP general
    else if (cmd.includes('tshark') && cmd.includes('http')) {
        terminal.innerHTML += `<span style="color: #8b949e;">   45   5.234567 192.168.1.100 → 192.168.1.50 HTTP GET /
   67   7.123456 192.168.1.100 → 192.168.1.50 HTTP GET /login  
   89   9.345678 192.168.1.100 → 192.168.1.50 <span style="color: #ffa657;">HTTP POST /login</span>

<span style="color: #7ee787;">💡 Filter by attacker MAC: -Y "http && eth.src == aa:bb:cc:11:22:33"</span>
</span>`;
    }
    // STRINGS
    else if (cmd.includes('strings') && (cmd.includes('flag') || cmd.includes('pass'))) {
        terminal.innerHTML += `<span style="color: #7ee787;">password=secXplore{4rp_sp00f_m1tm_4tt4ck}</span>\n`;
    }
    // ARP -a
    else if (cmd.includes('arp -a') || cmd === 'arp') {
        terminal.innerHTML += `<span style="color: #8b949e;">? (192.168.1.1) at aa:bb:cc:11:22:33 [ether] on eth0
? (192.168.1.50) at aa:bb:cc:dd:ee:50 [ether] on eth0
? (192.168.1.254) at aa:bb:cc:11:22:33 [ether] on eth0

<span style="color: #f97583;">⚠ WARNING: 192.168.1.1 and 192.168.1.254 have SAME MAC!</span>
</span>`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};
// REVERSE 1: ASSEMBLY PASSWORD CHECK
// ============================================
window.executeAsmCommand = function() {
    const input = document.getElementById('asmCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('asmTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  objdump -d [binary]          - Disassemble binary
  objdump -s -j .rodata [bin]  - Show read-only data
  strings [binary]             - Extract printable strings
  file [binary]                - File type information
  readelf -a [binary]          - ELF file info
  ltrace ./[binary] [args]     - Library call trace
  strace ./[binary] [args]     - System call trace
  ./password_checker [pass]    - Run the binary
  gdb ./[binary]               - Debug with GDB
  r2 [binary]                  - Radare2 analysis
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           REVERSE ENGINEERING WORKSTATION                    │
│           x86-64 Assembly Analyzer                           │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">Binary loaded: password_checker</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // FILE
    else if (cmd.includes('file ')) {
        terminal.innerHTML += `<span style="color: #8b949e;">password_checker: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped</span>\n`;
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        if (cmd.includes('grep') && (cmd.includes('pass') || cmd.includes('flag'))) {
            terminal.innerHTML += `<span style="color: #ffa657;">sup3r_s3cr3t_p4ss</span>
<span style="color: #8b949e;">Enter password:</span>
<span style="color: #8b949e;">Wrong password!</span>
<span style="color: #8b949e;">Access granted!</span>\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
printf
strcmp
__libc_start_main
GLIBC_2.2.5
Enter password: 
<span style="color: #ffa657;">sup3r_s3cr3t_p4ss</span>
Wrong password!
Access granted!
Flag: secXplore{%s}
</span>`;
        }
    }
    // OBJDUMP disassemble
    else if (cmd.includes('objdump -d')) {
        terminal.innerHTML += `<span style="color: #8b949e;">password_checker:     file format elf64-x86-64

Disassembly of section .text:

0000000000401156 <check_password>:
  401156:   55                      push   %rbp
  401157:   48 89 e5                mov    %rsp,%rbp
  40115a:   48 83 ec 10             sub    $0x10,%rsp
  40115e:   48 89 7d f8             mov    %rdi,-0x8(%rbp)
  401162:   48 8b 45 f8             mov    -0x8(%rbp),%rax
  401166:   <span style="color: #ffa657;">48 8d 35 9b 0e 00 00    lea    0xe9b(%rip),%rsi  # 402008 "sup3r_s3cr3t_p4ss"</span>
  40116d:   48 89 c7                mov    %rax,%rdi
  401170:   e8 cb fe ff ff          call   401040 <strcmp@plt>
  401175:   85 c0                   test   %eax,%eax
  401177:   0f 94 c0                sete   %al
  40117a:   0f b6 c0                movzbl %al,%eax
  40117d:   c9                      leave
  40117e:   c3                      ret

<span style="color: #7ee787;">💡 The password "sup3r_s3cr3t_p4ss" is loaded at 401166!</span>
</span>`;
    }
    // OBJDUMP .rodata
    else if (cmd.includes('objdump') && cmd.includes('.rodata')) {
        terminal.innerHTML += `<span style="color: #8b949e;">Contents of section .rodata:
 402000 01000200 00000000 <span style="color: #ffa657;">73757033 725f7333  ........sup3r_s3</span>
 402010 <span style="color: #ffa657;">63723374 5f703473 73000000 00000000  cr3t_p4ss.......</span>
 402020 456e7465 72207061 7373776f 72643a20  Enter password: 
 402030 00000000 00000000 57726f6e 67207061  ........Wrong pa
</span>`;
    }
    // LTRACE
    else if (cmd.includes('ltrace')) {
        const arg = command.match(/ltrace\s+\.\/\S+\s+(\S+)/)?.[1] || 'test';
        if (arg === 'sup3r_s3cr3t_p4ss') {
            terminal.innerHTML += `<span style="color: #8b949e;">__libc_start_main(0x401180, 2, 0x7ffd...)
puts("Enter password: ")
<span style="color: #7ee787;">strcmp("sup3r_s3cr3t_p4ss", "sup3r_s3cr3t_p4ss") = 0</span>
printf("Access granted!\\nFlag: secXplore{%s}\\n", "4sm_r3v3rs3_3z")
+++ exited (status 0) +++
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">__libc_start_main(0x401180, 2, 0x7ffd...)
puts("Enter password: ")
<span style="color: #f97583;">strcmp("${arg}", "sup3r_s3cr3t_p4ss") = 1</span>
puts("Wrong password!")
+++ exited (status 1) +++
</span>`;
        }
    }
    // RUN BINARY
    else if (cmd.includes('./password_checker')) {
        const arg = command.match(/\.\/password_checker\s+(\S+)/)?.[1];
        if (arg === 'sup3r_s3cr3t_p4ss') {
            terminal.innerHTML += `<span style="color: #8b949e;">Enter password: 
<span style="color: #7ee787;">Access granted!
Flag: secXplore{4sm_r3v3rs3_3z}</span>
</span>`;
        } else if (arg) {
            terminal.innerHTML += `<span style="color: #8b949e;">Enter password: 
<span style="color: #f97583;">Wrong password!</span>
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: ./password_checker [password]</span>\n`;
        }
    }
    // READELF
    else if (cmd.includes('readelf')) {
        terminal.innerHTML += `<span style="color: #8b949e;">ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x401080
...
</span>`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};

//Reverse2 Crackme
window.executeCrackmeCommand = function() {
    const input = document.getElementById('crackmeCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('crackmeTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ./crackme_easy [serial]      - Run with serial key
  objdump -d crackme_easy      - Disassemble
  strings crackme_easy         - Extract strings
  file crackme_easy            - File info
  ltrace ./crackme_easy [arg]  - Library trace
  strace ./crackme_easy [arg]  - System trace
  gdb ./crackme_easy           - Debug
  r2 crackme_easy              - Radare2
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           CRACKME CHALLENGE                                  │
│           Serial Key Validator                               │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">Binary loaded: crackme_easy</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // FILE
    else if (cmd.includes('file ')) {
        terminal.innerHTML += `<span style="color: #8b949e;">crackme_easy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, not stripped</span>\n`;
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        terminal.innerHTML += `<span style="color: #8b949e;">Usage: ./crackme_easy [serial]
Invalid serial!
<span style="color: #ffa657;">Congratulations! Flag: secXplore{cr4ckm3_%s}</span>
DEADBEEF
XOR key: 0x42
Expected: R3V3RS3
</span>`;
    }
    // OBJDUMP
    else if (cmd.includes('objdump')) {
        terminal.innerHTML += `<span style="color: #8b949e;">crackme_easy:     file format elf64-x86-64

Disassembly of section .text:

0000000000401200 <validate_serial>:
  401200:   push   %rbp
  401201:   mov    %rsp,%rbp
  401204:   mov    %rdi,-0x8(%rbp)        ; store input
  401208:   mov    $0x0,%ecx              ; counter = 0
  40120d:   <span style="color: #ffa657;">mov    $0x42,%edx              ; XOR key = 0x42</span>
  401212:   mov    -0x8(%rbp),%rax
  401216:   movzbl (%rax,%rcx,1),%eax     ; get char
  40121a:   <span style="color: #ffa657;">xor    %edx,%eax               ; XOR with key</span>
  40121c:   lea    expected(%rip),%rsi
  401223:   movzbl (%rsi,%rcx,1),%esi     ; get expected
  401227:   cmp    %esi,%eax              ; compare
  401229:   jne    fail
  ...
  
<span style="color: #7ee787;">💡 Algorithm: input[i] XOR 0x42 == expected[i]</span>
<span style="color: #7ee787;">💡 To reverse: expected[i] XOR 0x42 = correct_serial[i]</span>
</span>`;
    }
    // LTRACE
    else if (cmd.includes('ltrace')) {
        const arg = command.match(/ltrace\s+\.\/\S+\s+(\S+)/)?.[1] || 'TEST';
        if (arg === 'R3V3RS3') {
            terminal.innerHTML += `<span style="color: #8b949e;">__libc_start_main(...)
strlen("R3V3RS3") = 7
<span style="color: #7ee787;">Validation passed!</span>
printf("Congratulations! Flag: secXplore{cr4ckm3_%s}\\n", "b1n4ry_m4st3r")
+++ exited (status 0) +++
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">__libc_start_main(...)
strlen("${arg}") = ${arg.length}
<span style="color: #f97583;">puts("Invalid serial!")</span>
+++ exited (status 1) +++
</span>`;
        }
    }
    // RUN BINARY
    else if (cmd.includes('./crackme_easy')) {
        const arg = command.match(/\.\/crackme_easy\s+(\S+)/)?.[1];
        if (arg === 'R3V3RS3') {
            terminal.innerHTML += `<span style="color: #7ee787;">Congratulations! Flag: secXplore{cr4ckm3_b1n4ry_m4st3r}</span>\n`;
        } else if (arg) {
            terminal.innerHTML += `<span style="color: #f97583;">Invalid serial!</span>\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: ./crackme_easy [serial]</span>\n`;
        }
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};
// REVERSE 3: OBFUSCATED CODE
// ============================================
window.executeObfuscatedCommand = function() {
    const input = document.getElementById('obfuscatedCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('obfuscatedTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  cat obfuscated.js            - View raw code
  beautify obfuscated.js       - Format/beautify code
  deobfuscate obfuscated.js    - Attempt deobfuscation
  strings obfuscated.js        - Extract strings
  grep [pattern] obfuscated.js - Search in code
  decode base64 [string]       - Decode Base64
  decode hex [string]          - Decode Hex
  node obfuscated.js           - Run the script
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           JS DEOBFUSCATION WORKBENCH                         │
│           Code Analysis Tool                                 │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">File loaded: obfuscated.js</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // CAT
    else if (cmd.includes('cat ') && cmd.includes('obfuscated')) {
        terminal.innerHTML += `<span style="color: #8b949e;">var _0x4e8a=['\\x73\\x65\\x63\\x58\\x70\\x6c\\x6f\\x72\\x65',
'\\x7b\\x6f\\x62\\x66\\x75\\x73\\x63\\x34\\x74\\x33\\x64',
'\\x5f\\x6a\\x73\\x5f\\x63\\x30\\x64\\x33\\x7d'];
(function(_0x1a2b3c,_0x4d5e6f){var _0x7g8h9i=function(_0xjklmno){
while(--_0xjklmno){_0x1a2b3c['push'](_0x1a2b3c['shift']());}};
_0x7g8h9i(++_0x4d5e6f);}(_0x4e8a,0x1b3));
var _0xgetFlag=function(){return _0x4e8a[0]+_0x4e8a[1]+_0x4e8a[2];};
eval(atob('Y29uc29sZS5sb2coX zB4Z2V0RmxhZygpKQ=='));
</span>`;
    }
    // BEAUTIFY
    else if (cmd.includes('beautify')) {
        terminal.innerHTML += `<span style="color: #8b949e;">var _0x4e8a = [
    '\\x73\\x65\\x63\\x58\\x70\\x6c\\x6f\\x72\\x65',     // "secXplore"
    '\\x7b\\x6f\\x62\\x66\\x75\\x73\\x63\\x34\\x74\\x33\\x64',  // "{obfusc4t3d"
    '\\x5f\\x6a\\x73\\x5f\\x63\\x30\\x64\\x33\\x7d'      // "_js_c0d3}"
];

var _0xgetFlag = function() {
    return _0x4e8a[0] + _0x4e8a[1] + _0x4e8a[2];
};

<span style="color: #7ee787;">// Decoded hex strings: "secXplore" + "{obfusc4t3d" + "_js_c0d3}"</span>
<span style="color: #7ee787;">// Flag: secXplore{obfusc4t3d_js_c0d3}</span>
</span>`;
    }
    // DEOBFUSCATE
    else if (cmd.includes('deobfuscate')) {
        terminal.innerHTML += `<span style="color: #8b949e;">Analyzing obfuscation patterns...

<span style="color: #ffa657;">Found techniques:</span>
  ✓ Hex-encoded strings (\\x73\\x65\\x63...)
  ✓ Array rotation
  ✓ Base64 eval payload
  ✓ Variable name mangling

<span style="color: #7ee787;">Decoded strings:</span>
  _0x4e8a[0] = "secXplore"
  _0x4e8a[1] = "{obfusc4t3d"
  _0x4e8a[2] = "_js_c0d3}"

<span style="color: #7ee787;">🎉 FLAG: secXplore{obfusc4t3d_js_c0d3}</span>
</span>`;
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        if (cmd.includes('grep') || cmd.includes('sec') || cmd.includes('flag')) {
            terminal.innerHTML += `<span style="color: #7ee787;">secXplore{obfusc4t3d_js_c0d3}</span>\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">_0x4e8a
_0x7g8h9i
_0xgetFlag
atob
eval
push
shift
<span style="color: #ffa657;">secXplore{obfusc4t3d_js_c0d3}</span>
</span>`;
        }
    }
    // DECODE BASE64
    else if (cmd.includes('decode base64') || cmd.includes('decode b64')) {
        if (cmd.includes('Y29uc29sZS5sb2coXzB4Z2V0RmxhZygpKQ==')) {
            terminal.innerHTML += `<span style="color: #7ee787;">console.log(_0xgetFlag())</span>\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: decode base64 [base64_string]</span>\n`;
        }
    }
    // DECODE HEX
    else if (cmd.includes('decode hex')) {
        terminal.innerHTML += `<span style="color: #8b949e;">\\x73\\x65\\x63\\x58\\x70\\x6c\\x6f\\x72\\x65 = "secXplore"
\\x7b\\x6f\\x62\\x66\\x75\\x73\\x63\\x34\\x74\\x33\\x64 = "{obfusc4t3d"
\\x5f\\x6a\\x73\\x5f\\x63\\x30\\x64\\x33\\x7d = "_js_c0d3}"
</span>`;
    }
    // NODE run
    else if (cmd.includes('node ')) {
        terminal.innerHTML += `<span style="color: #7ee787;">secXplore{obfusc4t3d_js_c0d3}</span>\n`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};
// MOBILE 1: APK STRING ANALYSIS
// ============================================
window.executeApkCommand = function() {
    const input = document.getElementById('apkCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('apkTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  apktool d [apk]              - Decompile APK
  jadx [apk] -d [output]       - Decompile to Java
  unzip [apk] -d [dir]         - Extract APK contents
  aapt dump badging [apk]      - Package info
  strings [apk]                - Extract strings
  grep -r [pattern] [dir]      - Search in files
  cat [file]                   - View file contents
  find [dir] -name [pattern]   - Find files
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           ANDROID APK ANALYZER                               │
│           Mobile Security Workstation                        │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #8b949e;">APK loaded: suspicious_app.apk</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // FILE
    else if (cmd.includes('file ')) {
        terminal.innerHTML += `<span style="color: #8b949e;">suspicious_app.apk: Zip archive data, at least v2.0 to extract</span>\n`;
    }
    // AAPT
    else if (cmd.includes('aapt')) {
        terminal.innerHTML += `<span style="color: #8b949e;">package: name='com.suspicious.app' versionCode='1' versionName='1.0'
sdkVersion:'21'
targetSdkVersion:'33'
application-label:'Suspicious App'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.ACCESS_FINE_LOCATION'
</span>`;
    }
    // APKTOOL
    else if (cmd.includes('apktool')) {
        terminal.innerHTML += `<span style="color: #8b949e;">I: Using Apktool 2.7.0
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: ~/.apktool/framework/1.apk
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...

<span style="color: #7ee787;">✓ Decompiled to: suspicious_app/</span>
Structure:
  ├── AndroidManifest.xml
  ├── apktool.yml
  ├── res/
  │   └── values/
  │       └── <span style="color: #ffa657;">strings.xml</span>
  ├── smali/
  └── assets/
      └── <span style="color: #ffa657;">config.json</span>
</span>`;
    }
    // JADX
    else if (cmd.includes('jadx')) {
        terminal.innerHTML += `<span style="color: #8b949e;">INFO  - loading ...
INFO  - processing ...
INFO  - done

<span style="color: #7ee787;">✓ Decompiled to Java source</span>
Check: output/sources/com/suspicious/app/
</span>`;
    }
    // STRINGS
    else if (cmd.includes('strings')) {
        if (cmd.includes('grep') && (cmd.includes('api') || cmd.includes('key') || cmd.includes('secret') || cmd.includes('flag'))) {
            terminal.innerHTML += `<span style="color: #ffa657;">API_KEY=sk_live_12345abcdef
SECRET_TOKEN=secXplore{4pk_str1ngs_3xtr4ct3d}
DEBUG_MODE=true</span>\n`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">classes.dex
resources.arsc
AndroidManifest.xml
META-INF/
res/
assets/
DEBUG_MODE
<span style="color: #ffa657;">API_KEY=sk_live_12345abcdef</span>
<span style="color: #ffa657;">SECRET_TOKEN=secXplore{4pk_str1ngs_3xtr4ct3d}</span>
BuildConfig
MainActivity
</span>`;
        }
    }
    // CAT strings.xml
    else if (cmd.includes('cat') && cmd.includes('strings.xml')) {
        terminal.innerHTML += `<span style="color: #8b949e;">&lt;?xml version="1.0" encoding="utf-8"?&gt;
&lt;resources&gt;
    &lt;string name="app_name"&gt;Suspicious App&lt;/string&gt;
    &lt;string name="api_endpoint"&gt;https://api.suspicious.com&lt;/string&gt;
    <span style="color: #ffa657;">&lt;string name="secret_flag"&gt;secXplore{4pk_str1ngs_3xtr4ct3d}&lt;/string&gt;</span>
    &lt;string name="debug_key"&gt;12345-DEBUG-KEY&lt;/string&gt;
&lt;/resources&gt;
</span>`;
    }
    // CAT config.json
    else if (cmd.includes('cat') && cmd.includes('config.json')) {
        terminal.innerHTML += `<span style="color: #8b949e;">{
  "api_url": "https://api.suspicious.com",
  "debug": true,
  <span style="color: #ffa657;">"secret": "secXplore{4pk_str1ngs_3xtr4ct3d}",</span>
  "version": "1.0"
}
</span>`;
    }
    // GREP
    else if (cmd.includes('grep')) {
        if (cmd.includes('secret') || cmd.includes('flag') || cmd.includes('key')) {
            terminal.innerHTML += `<span style="color: #8b949e;">res/values/strings.xml:    <span style="color: #ffa657;">&lt;string name="secret_flag"&gt;secXplore{4pk_str1ngs_3xtr4ct3d}&lt;/string&gt;</span>
assets/config.json:    <span style="color: #ffa657;">"secret": "secXplore{4pk_str1ngs_3xtr4ct3d}"</span>
</span>`;
        }
    }
    // FIND
    else if (cmd.includes('find')) {
        terminal.innerHTML += `<span style="color: #8b949e;">./res/values/strings.xml
./res/values/colors.xml
./res/layout/activity_main.xml
./assets/config.json
./smali/com/suspicious/app/MainActivity.smali
./smali/com/suspicious/app/BuildConfig.smali
</span>`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};
// MOBILE 2: ROOT DETECTION BYPASS
// ============================================
window.executeRootCommand = function() {
    const input = document.getElementById('rootCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('rootTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  jadx [apk] -d output/        - Decompile to Java
  apktool d [apk]              - Decompile to smali
  apktool b [dir]              - Rebuild APK
  frida -U -f [package] -l [script]  - Frida hook
  objection -g [package] explore     - Objection shell
  grep -r [pattern] output/    - Search code
  cat [file]                   - View file
  smali2java [file]            - Convert smali
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           ROOT DETECTION BYPASS LAB                          │
│           Frida Instrumentation Framework                    │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #f97583;">⚠ Root detection active!</span>
<span style="color: #8b949e;">Target: SecureBank.apk</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // JADX
    else if (cmd.includes('jadx')) {
        terminal.innerHTML += `<span style="color: #8b949e;">INFO  - loading ...
INFO  - processing ...
INFO  - done

<span style="color: #7ee787;">✓ Decompiled to: output/</span>
Found root detection in: output/sources/com/securebank/app/security/RootDetector.java
</span>`;
    }
    // GREP for root detection
    else if (cmd.includes('grep') && (cmd.includes('root') || cmd.includes('isrooted') || cmd.includes('su'))) {
        terminal.innerHTML += `<span style="color: #8b949e;">output/sources/com/securebank/app/security/RootDetector.java:
    <span style="color: #ffa657;">public static boolean isRooted() {</span>
    <span style="color: #ffa657;">    if (checkSuBinary()) return true;</span>
    <span style="color: #ffa657;">    if (checkRootApps()) return true;</span>
    <span style="color: #ffa657;">    if (checkBusybox()) return true;</span>
    <span style="color: #ffa657;">    return false;</span>
    <span style="color: #ffa657;">}</span>
</span>
<span style="color: #7ee787;">💡 Hook isRooted() to return false!</span>
`;
    }
    // CAT RootDetector.java
    else if (cmd.includes('cat') && cmd.includes('rootdetector')) {
        terminal.innerHTML += `<span style="color: #8b949e;">package com.securebank.app.security;

public class RootDetector {
    
    <span style="color: #ffa657;">public static boolean isRooted() {</span>
        if (checkSuBinary()) return true;
        if (checkRootApps()) return true;
        if (checkBusybox()) return true;
        if (checkRWPaths()) return true;
        return false;
    }
    
    private static boolean checkSuBinary() {
        String[] paths = {"/system/bin/su", "/system/xbin/su", 
                         "/sbin/su", "/data/local/xbin/su"};
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }
    
    // When bypassed, shows debug menu with flag
    <span style="color: #7ee787;">// Debug flag: secXplore{r00t_d3t3ct10n_byp4ss3d}</span>
}
</span>`;
    }
    // FRIDA
    else if (cmd.includes('frida')) {
        if (cmd.includes('bypass.js') || cmd.includes('-l')) {
            terminal.innerHTML += `<span style="color: #8b949e;">     ____
    / _  |   Frida 16.0.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system

[USB::Device]-> <span style="color: #7ee787;">Spawned 'com.securebank.app'. Resuming...</span>
[*] Hooking RootDetector.isRooted()...
[*] <span style="color: #7ee787;">isRooted() hooked! Always returning false</span>
[*] Root detection bypassed!
[*] Debug menu unlocked!
[*] <span style="color: #7ee787;">Flag: secXplore{r00t_d3t3ct10n_byp4ss3d}</span>
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: frida -U -f com.securebank.app -l bypass.js</span>\n`;
        }
    }
    // OBJECTION
    else if (cmd.includes('objection')) {
        if (cmd.includes('sslpinning') || cmd.includes('root')) {
            terminal.innerHTML += `<span style="color: #8b949e;">com.securebank.app on (Android: 13) [usb] # android root disable
<span style="color: #7ee787;">(agent) Registering job. Hooks will be executed when methods are called.</span>
<span style="color: #7ee787;">(agent) Root detection bypass applied!</span>

com.securebank.app on (Android: 13) [usb] # 
<span style="color: #7ee787;">Debug menu now accessible!</span>
<span style="color: #7ee787;">Flag: secXplore{r00t_d3t3ct10n_byp4ss3d}</span>
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">com.securebank.app on (Android: 13) [usb] #

Type 'android root disable' to bypass root detection
Type 'android sslpinning disable' to bypass SSL pinning
</span>`;
        }
    }
    // APKTOOL
    else if (cmd.includes('apktool')) {
        if (cmd.includes(' b ')) {
            terminal.innerHTML += `<span style="color: #8b949e;">I: Using Apktool 2.7.0
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
<span style="color: #7ee787;">I: Built apk: SecureBank/dist/SecureBank.apk</span>

<span style="color: #ffa657;">⚠ Don't forget to sign the APK!</span>
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">I: Using Apktool 2.7.0
I: Decompiling SecureBank.apk...
<span style="color: #7ee787;">I: Done. Output: SecureBank/</span>

Edit: SecureBank/smali/com/securebank/app/security/RootDetector.smali
Change: const/4 v0, 0x1 -> const/4 v0, 0x0 (isRooted returns false)
</span>`;
        }
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};

//Mobile 3 SSL
// ============================================
// MOBILE 3: SSL PINNING BYPASS (continued)
// ============================================
window.executeSslCommand = function() {
    const input = document.getElementById('sslCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('sslTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `<span style="color: #7ee787;">$</span> ${escapeHtml(command)}\n`;
    
    const cmd = command.toLowerCase();
    
    // HELP
    if (cmd === 'help') {
        terminal.innerHTML += `<span style="color: #58a6ff;">
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  jadx [apk] -d output/        - Decompile to Java
  grep -r [pattern] output/    - Search in code
  cat [file]                   - View file
  frida -U -f [package] -l [script]  - Frida hook
  objection -g [package] explore     - Objection shell
  openssl s_client -connect [host:port]  - Test SSL
  burp                         - Setup Burp proxy info
  intercept                    - Show intercepted traffic
  clear                        - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</span>`;
    }
    // CLEAR
    else if (cmd === 'clear') {
        terminal.innerHTML = `<span style="color: #58a6ff;">┌──────────────────────────────────────────────────────────────┐
│           SSL PINNING BYPASS LAB                             │
│           Certificate Pinning Analysis                       │
└──────────────────────────────────────────────────────────────┘</span>

<span style="color: #f97583;">⚠ SSL Certificate Pinning detected!</span>
<span style="color: #8b949e;">Target: SecretChat.apk</span>
<span style="color: #8b949e;">$ </span>`;
        input.value = '';
        return;
    }
    // JADX
    else if (cmd.includes('jadx')) {
        terminal.innerHTML += `<span style="color: #8b949e;">INFO  - loading ...
INFO  - processing ...
INFO  - done

<span style="color: #7ee787;">✓ Decompiled to: output/</span>
Found SSL pinning in:
  - output/sources/com/secretchat/app/network/SSLPinner.java
  - output/sources/com/secretchat/app/network/TrustManagerImpl.java
</span>`;
    }
    // GREP for SSL pinning
    else if (cmd.includes('grep') && (cmd.includes('certificate') || cmd.includes('pinning') || cmd.includes('trust') || cmd.includes('ssl'))) {
        terminal.innerHTML += `<span style="color: #8b949e;">output/sources/com/secretchat/app/network/SSLPinner.java:
    <span style="color: #ffa657;">CertificatePinner pinner = new CertificatePinner.Builder()</span>
    <span style="color: #ffa657;">    .add("api.secretchat.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")</span>
    <span style="color: #ffa657;">    .build();</span>

output/sources/com/secretchat/app/network/TrustManagerImpl.java:
    <span style="color: #ffa657;">public void checkServerTrusted(X509Certificate[] chain, String authType) {</span>
    <span style="color: #ffa657;">    // Custom certificate validation</span>
    <span style="color: #ffa657;">}</span>
</span>
<span style="color: #7ee787;">💡 Found OkHttp CertificatePinner and custom TrustManager!</span>
`;
    }
    // CAT SSLPinner.java
    else if (cmd.includes('cat') && (cmd.includes('sslpinner') || cmd.includes('trustmanager'))) {
        terminal.innerHTML += `<span style="color: #8b949e;">package com.secretchat.app.network;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

public class SSLPinner {
    
    private static final String API_HOST = "api.secretchat.com";
    <span style="color: #ffa657;">private static final String PIN_SHA256 = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";</span>
    
    public static OkHttpClient getPinnedClient() {
        <span style="color: #ffa657;">CertificatePinner pinner = new CertificatePinner.Builder()</span>
            <span style="color: #ffa657;">.add(API_HOST, PIN_SHA256)</span>
            <span style="color: #ffa657;">.build();</span>
            
        return new OkHttpClient.Builder()
            .certificatePinner(pinner)
            .build();
    }
    
    // Bypass this to intercept traffic
    // Secret endpoint: /api/secret returns flag
}
</span>`;
    }
    // FRIDA
    else if (cmd.includes('frida')) {
        if (cmd.includes('ssl') || cmd.includes('bypass') || cmd.includes('-l')) {
            terminal.innerHTML += `<span style="color: #8b949e;">     ____
    / _  |   Frida 16.0.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system

[USB::Device]-> <span style="color: #7ee787;">Spawned 'com.secretchat.app'. Resuming...</span>
[*] Hooking TrustManager...
[*] <span style="color: #7ee787;">TrustManager.checkServerTrusted() bypassed!</span>
[*] Hooking CertificatePinner...
[*] <span style="color: #7ee787;">CertificatePinner.check() bypassed!</span>
[*] SSL Pinning disabled!
[*] 
[*] <span style="color: #ffa657;">Now configure Burp proxy and intercept traffic!</span>
[*] Type 'intercept' to see captured data
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">Usage: frida -U -f com.secretchat.app -l ssl_bypass.js</span>\n`;
        }
    }
    // OBJECTION
    else if (cmd.includes('objection')) {
        if (cmd.includes('sslpinning') || cmd.includes('ssl')) {
            terminal.innerHTML += `<span style="color: #8b949e;">com.secretchat.app on (Android: 13) [usb] # android sslpinning disable
<span style="color: #7ee787;">(agent) Registering job to disable SSL Pinning...</span>
<span style="color: #7ee787;">(agent) Found okhttp3.CertificatePinner, hooking check() method</span>
<span style="color: #7ee787;">(agent) Found TrustManagerImpl, hooking checkServerTrusted()</span>
<span style="color: #7ee787;">(agent) SSL Pinning disabled!</span>

com.secretchat.app on (Android: 13) [usb] # 
<span style="color: #ffa657;">Now intercept HTTPS traffic with Burp!</span>
<span style="color: #ffa657;">Type 'intercept' to see captured API response</span>
</span>`;
        } else {
            terminal.innerHTML += `<span style="color: #8b949e;">com.secretchat.app on (Android: 13) [usb] #

Commands:
  android sslpinning disable  - Disable SSL pinning
  android root disable        - Disable root detection
  memory list modules         - List loaded modules
</span>`;
        }
    }
    // BURP setup info
    else if (cmd === 'burp') {
        terminal.innerHTML += `<span style="color: #8b949e;">
<span style="color: #58a6ff;">━━━ Burp Suite Proxy Setup ━━━</span>

1. Start Burp Suite Professional/Community
2. Configure proxy listener: 0.0.0.0:8080
3. Export Burp CA certificate
4. Install CA cert on Android device:
   adb push burp.der /sdcard/
   Settings → Security → Install certificate

5. Configure device proxy:
   WiFi Settings → Modify network → Manual proxy
   Host: [Your IP]  Port: 8080

6. Run Frida/Objection SSL bypass script
7. Launch app and intercept traffic!

<span style="color: #7ee787;">Target endpoint: https://api.secretchat.com/api/secret</span>
</span>`;
    }
    // OPENSSL
    else if (cmd.includes('openssl')) {
        terminal.innerHTML += `<span style="color: #8b949e;">CONNECTED(00000003)
depth=2 C = US, O = DigiCert Inc, CN = DigiCert Global Root CA
verify return:1
depth=1 C = US, O = DigiCert Inc, CN = DigiCert SHA2 Extended Validation Server CA
verify return:1
depth=0 businessCategory = Private Organization, CN = api.secretchat.com
verify return:1
---
Certificate chain
 0 s:CN = api.secretchat.com
   i:CN = DigiCert SHA2 Extended Validation Server CA
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFjTCCBHWgAwIBAgIQDp...
-----END CERTIFICATE-----

<span style="color: #7ee787;">💡 Extract pin: echo | openssl s_client -connect api.secretchat.com:443 | openssl x509 -pubkey -noout | openssl sha256 -binary | base64</span>
</span>`;
    }
    // INTERCEPT - show captured traffic
    else if (cmd === 'intercept') {
        terminal.innerHTML += `<span style="color: #8b949e;">
<span style="color: #58a6ff;">━━━ Intercepted HTTPS Traffic ━━━</span>

<span style="color: #ffa657;">▶ Request:</span>
GET /api/secret HTTP/1.1
Host: api.secretchat.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
User-Agent: SecretChat/1.0 Android

<span style="color: #7ee787;">◀ Response:</span>
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "message": "Welcome to the secret API",
  <span style="color: #7ee787;">"flag": "secXplore{ssl_p1nn1ng_byp4ss3d_m1tm}"</span>,
  "secret_data": {
    "users_count": 15847,
    "messages_today": 284719
  }
}

<span style="color: #7ee787;">🎉 FLAG FOUND: secXplore{ssl_p1nn1ng_byp4ss3d_m1tm}</span>
</span>`;
    }
    // Unknown
    else {
        terminal.innerHTML += `<span style="color: #f97583;">bash: ${command.split(' ')[0]}: command not found</span>\n`;
    }
    
    terminal.innerHTML += `<span style="color: #8b949e;">$ </span>`;
    input.value = '';
    terminal.scrollTop = terminal.scrollHeight;
    input.focus();
};

// ============================================
// SHARED UTILITY FUNCTIONS
// ============================================

// Escape HTML to prevent XSS in terminal output
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Toggle hint visibility
window.toggleHint = function(hintId) {
    const hint = document.getElementById(hintId);
    if (hint) {
        if (hint.style.display === 'none') {
            hint.style.display = 'block';
            // Track hint usage for scoring
            console.log(`Hint ${hintId} revealed - deduct points`);
        } else {
            hint.style.display = 'none';
        }
    }
};

// Generic terminal scroll helper
function scrollTerminalToBottom(terminalId) {
    const terminal = document.getElementById(terminalId);
    if (terminal) {
        terminal.scrollTop = terminal.scrollHeight;
    }
}

// Add keyboard event listeners for all terminals
document.addEventListener('DOMContentLoaded', function() {
    // Auto-focus input fields when clicking on terminals
    document.querySelectorAll('.terminal').forEach(terminal => {
        terminal.addEventListener('click', function() {
            const input = this.querySelector('input[type="text"]');
            if (input) input.focus();
        });
    });
});

// ============================================
// 7. NAVIGATION & MODAL EXPORTS
// ============================================

// เรียกจากหน้า challenge.html
window.openChallengeList = function(category) {
    // 1. กรองโจทย์ตามหมวดหมู่ และเรียงตามคะแนน (น้อยไปมาก)
    const catChallenges = dbChallenges
        .filter(c => c.category === category)
        .sort((a, b) => a.score_base - b.score_base); // <--- เพิ่มบรรทัดนี้
    
    const modal = document.getElementById('challengeModal');
    const list = document.getElementById('challengeList');
    const modalTitle = document.getElementById('modalTitle');
    const progressText = document.getElementById('progressText');
    const progressFill = document.getElementById('progressFill');
    
    // 2. ตั้งชื่อหัวข้อ
    const categoryNames = {
        web: '🌐 Web Security',
        crypto: '🔐 Cryptography',
        forensics: '🔍 Digital Forensics',
        network: '📡 Network Security',
        reverse: '⚙️ Reverse Engineering',
        mobile: '📱 Mobile Security'
    };
    modalTitle.textContent = categoryNames[category] || category.toUpperCase();
    
    // 3. คำนวณ Progress
    const total = catChallenges.length;
    const solvedCount = catChallenges.filter(c => userProgressDB[c.challenge_id]).length;
    const percent = total > 0 ? Math.round((solvedCount / total) * 100) : 0;

    if (progressText && progressFill) {
        progressText.textContent = `${solvedCount} of ${total} completed (${percent}%)`;
        progressFill.style.width = `${percent}%`;
    }

    // 4. สร้างรายการโจทย์ (List)
    list.innerHTML = '';
    if (catChallenges.length === 0) {
        list.innerHTML = '<p style="text-align:center; padding:2rem; color:#888;">No challenges available in this category.</p>';
    }

    catChallenges.forEach(c => {
        const shortId = Object.keys(ID_MAPPING).find(key => ID_MAPPING[key] === c.title);
        const isSolved = userProgressDB[c.challenge_id];
        
        const statusBadge = isSolved 
            ? '<div class="status-badge status-completed">COMPLETE</div>' 
            : '<div class="status-badge status-not-started">START</div>';
            
        const item = document.createElement('div');
        item.className = `challenge-item ${isSolved ? 'completed' : ''}`;
        item.innerHTML = `
            <div class="challenge-header">
                <div class="challenge-name">${c.title}</div>
                <div class="challenge-right">
                    ${statusBadge}
                    <div class="challenge-points">${c.score_base} pts</div>
                </div>
            </div>
            <div class="challenge-description">${c.description}</div>
            <div class="challenge-meta">
               <span class="difficulty-badge difficulty-${c.difficulty}">${c.difficulty}</span>
            </div>
        `;
        
        // Logic การเปิด Modal
        if (shortId && interactiveChallenges[shortId]) {
            item.onclick = () => openInteractiveChallenge(shortId);
        } else if (c.interactive_id && interactiveChallenges[c.interactive_id]) {
            item.onclick = () => openInteractiveChallenge(c.interactive_id);
        } else {
            item.onclick = () => alert(`Challenge UI not ready for: ${c.title}`);
        }
        
        list.appendChild(item);
    });

    modal.classList.add('active');
};

window.closeModal = function() {
    document.getElementById('challengeModal').classList.remove('active');
};

window.confirmBackToCategory = function() {
    document.getElementById('interactiveModal').classList.remove('active');
};

// Add at the END of challenge.js
import { checkFlagSecure, loadChallengesSecure } from './challenge-secure.js';

// Replace the insecure checkFlag function
window.checkFlag = checkFlagSecure;
