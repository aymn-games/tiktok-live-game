// dotenv يحمّل متغيرات البيئة تلقائياً من ملف .env أثناء التطوير المحلي
// (على منصات النشر مثل Render/Railway/Vercel تضبط المتغيرات من لوحتها مباشرة، وهذا السطر ما يأثر عليها)
require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Server } = require('socket.io');
const { WebcastPushConnection } = require('tiktok-live-connector');
const cors = require('cors');

const app = express();

// ==== إعدادات TikTok Login Kit (OAuth 2.0) ====
// خذ هذي القيم من TikTok for Developers -> Manage apps -> Login Kit
// وحطها كمتغيرات بيئة (Environment Variables) على منصة النشر، لا تكتبها بالكود مباشرة.
const {
    TIKTOK_CLIENT_KEY,
    TIKTOK_CLIENT_SECRET,
    TIKTOK_REDIRECT_URI,      // مثال: https://your-backend-host.com/auth/callback
    SESSION_SECRET,
    NODE_ENV
} = process.env;

if (!TIKTOK_CLIENT_KEY || !TIKTOK_CLIENT_SECRET || !TIKTOK_REDIRECT_URI) {
    console.warn('⚠️ تحذير: متغيرات TikTok Login Kit (CLIENT_KEY/CLIENT_SECRET/REDIRECT_URI) غير مكتملة. تسجيل الدخول لن يعمل حتى تضبطها.');
}

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const sessionMiddleware = session({
    secret: SESSION_SECRET || crypto.randomBytes(32).toString('hex'), // يفضّل ضبط SESSION_SECRET ثابت بالبيئة
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: NODE_ENV === 'production', // يتطلب HTTPS في بيئة الإنتاج
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000 // يوم واحد
    }
});
app.use(sessionMiddleware);

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: true, credentials: true }
});

// مشاركة نفس الجلسة (session) بين Express وSocket.IO (يتطلب Socket.IO v4.6+)
io.engine.use(sessionMiddleware);

function requireAuth(req, res, next) {
    if (req.session && req.session.user) return next();
    return res.redirect('/login.html');
}

// حماية اتصال الـ socket نفسه: ما نسمح لأي اتصال إلا لو صاحبه مسجل دخول فعلاً
io.use((socket, next) => {
    const req = socket.request;
    if (req.session && req.session.user) {
        socket.user = req.session.user;
        return next();
    }
    next(new Error('unauthorized'));
});

function generatePkcePair() {
    const verifier = crypto.randomBytes(48).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

// 1) بدء تسجيل الدخول: تحويل المستخدم لصفحة تيك توك الرسمية
app.get('/auth/login', (req, res) => {
    if (!TIKTOK_CLIENT_KEY || !TIKTOK_REDIRECT_URI) {
        return res.status(500).send('إعدادات تسجيل الدخول غير مكتملة على السيرفر.');
    }

    const state = crypto.randomBytes(16).toString('hex');
    const { verifier, challenge } = generatePkcePair();
    req.session.oauthState = state;
    req.session.codeVerifier = verifier;

    const url = new URL('https://www.tiktok.com/v2/auth/authorize/');
    url.searchParams.set('client_key', TIKTOK_CLIENT_KEY);
    url.searchParams.set('scope', 'user.info.basic');
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('redirect_uri', TIKTOK_REDIRECT_URI);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    res.redirect(url.toString());
});

// 2) رابط الرجوع (Callback): تيك توك يرجّع المستخدم هنا بعد موافقته
app.get('/auth/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;

    if (error) {
        return res.redirect(`/login.html?error=${encodeURIComponent(error_description || error)}`);
    }
    if (!state || state !== req.session.oauthState) {
        return res.redirect(`/login.html?error=${encodeURIComponent('فشل التحقق من الجلسة (state mismatch)، حاول من جديد.')}`);
    }

    try {
        // 2.1) استبدال الكود المؤقت بـ access token (اتصال سيرفر-لسيرفر مباشر مع تيك توك)
        const tokenRes = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cache-Control': 'no-cache'
            },
            body: new URLSearchParams({
                client_key: TIKTOK_CLIENT_KEY,
                client_secret: TIKTOK_CLIENT_SECRET,
                code,
                grant_type: 'authorization_code',
                redirect_uri: TIKTOK_REDIRECT_URI,
                code_verifier: req.session.codeVerifier
            })
        });
        const tokenData = await tokenRes.json();

        if (!tokenData.access_token) {
            console.error('فشل استبدال الكود بتوكن:', tokenData);
            return res.redirect(`/login.html?error=${encodeURIComponent('فشل تسجيل الدخول عبر تيك توك.')}`);
        }

        // 2.2) نجيب فقط بيانات البروفايل العامة الأساسية (اسم العرض + الصورة) للتأكد من الهوية
        const userRes = await fetch(
            'https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url',
            { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
        );
        const userData = await userRes.json();
        const profile = userData?.data?.user;

        if (!profile?.open_id) {
            console.error('فشل جلب بيانات المستخدم:', userData);
            return res.redirect(`/login.html?error=${encodeURIComponent('تعذر التحقق من هوية الحساب.')}`);
        }

        // نخزّن فقط معرّف عام واسم عرض وصورة — بدون أي بيانات حساسة أو التوكن نفسه بالجلسة
        req.session.user = {
            openId: profile.open_id,
            displayName: profile.display_name,
            avatarUrl: profile.avatar_url
        };
        delete req.session.oauthState;
        delete req.session.codeVerifier;

        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.redirect(`/login.html?error=${encodeURIComponent('حدث خطأ غير متوقع أثناء تسجيل الدخول.')}`);
    }
});

// 3) تسجيل الخروج
app.get('/auth/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login.html');
    });
});

// 4) نقطة يستخدمها الفرونت اند للتحقق من حالة الجلسة الحالية
app.get('/auth/me', (req, res) => {
    res.json({
        authenticated: !!(req.session && req.session.user),
        user: req.session?.user || null
    });
});

// صفحة الدخول نفسها متاحة للجميع بدون تسجيل دخول
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// باقي لوحة التحكم محمية: ما تفتح إلا بعد تسجيل دخول ناجح
app.use(requireAuth, express.static(path.join(__dirname, 'public')));

// حالة الاتصال الحالية ببث التيك توك (اتصال واحد فقط في كل مرة)
let tiktokConnection = null;
let currentUsername = null;
let reconnectTimer = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;

// أسماء/أرقام هدية الوردة المعروفة على تيك توك (قد تختلف حسب النسخة)
const ROSE_GIFT_IDS = [5655];
const ROSE_GIFT_NAMES = ['rose', 'Rose'];

function isRoseGift(giftData) {
    return ROSE_GIFT_IDS.includes(giftData.giftId) || ROSE_GIFT_NAMES.includes(giftData.giftName);
}

async function disconnectCurrent() {
    if (tiktokConnection) {
        try { tiktokConnection.disconnect(); } catch (e) { /* تجاهل أخطاء القطع */ }
        tiktokConnection = null;
    }
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }
}

function attachTikTokListeners(socket, username, secretWord, reviveWord) {
    // 1. الشات: دخول اللاعبين بالكلمة السرية + طلبات الإقصاء بالأرقام + طلبات الإنعاش بالكلمة
    tiktokConnection.on('chat', (chatData) => {
        const comment = (chatData.comment || '').trim();

        if (comment === secretWord) {
            io.emit('new_player', { name: chatData.uniqueId });
            return;
        }

        if (reviveWord && comment === reviveWord) {
            io.emit('revive_request', { name: chatData.uniqueId });
            return;
        }

        if (comment !== '' && !isNaN(comment)) {
            io.emit('elimination_request', { name: chatData.uniqueId, targetNum: parseInt(comment, 10) });
        }
    });

    // 2. الهدايا: العودة التلقائية بالوردة بعد الإقصاء
    tiktokConnection.on('gift', (giftData) => {
        if (isRoseGift(giftData)) {
            io.emit('gift_revive', { name: giftData.uniqueId });
        }
        // نشر كل هدية للواجهة (يفيد لعرض تنبيهات هدايا عامة لو حبيت لاحقاً)
        io.emit('gift_received', {
            name: giftData.uniqueId,
            giftName: giftData.giftName,
            diamondCount: giftData.diamondCount || 0,
            repeatCount: giftData.repeatCount || 1
        });
    });

    // 2.1 المتابعات الجديدة أثناء البث
    tiktokConnection.on('follow', (followData) => {
        io.emit('new_follow', { name: followData.uniqueId });
    });

    // 2.2 اللايكات (اختياري لعرض عداد تفاعل حي)
    tiktokConnection.on('like', (likeData) => {
        io.emit('like_update', { name: likeData.uniqueId, totalLikes: likeData.totalLikeCount });
    });

    // 2.3 عدد المشاهدين اللحظي
    tiktokConnection.on('roomUser', (roomData) => {
        io.emit('viewer_count', { count: roomData.viewerCount });
    });

    // 3. مراقبة انقطاع الاتصال بالبث ومحاولة إعادة الاتصال تلقائياً
    tiktokConnection.on('disconnected', () => {
        io.emit('tiktok_status', { success: false, message: '⚠️ انقطع الاتصال بالبث، جاري محاولة إعادة الاتصال...' });
        attemptReconnect(username, secretWord, reviveWord);
    });

    tiktokConnection.on('streamEnd', () => {
        io.emit('tiktok_status', { success: false, message: '⏹️ انتهى البث المباشر.' });
        disconnectCurrent();
    });
}

function attemptReconnect(username, secretWord, reviveWord) {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        io.emit('tiktok_status', { success: false, message: '❌ فشلت كل محاولات إعادة الاتصال، تأكد أن البث مازال شغال.' });
        reconnectAttempts = 0;
        return;
    }
    reconnectAttempts += 1;
    const delayMs = 3000 * reconnectAttempts; // تأخير تصاعدي بسيط بين المحاولات

    reconnectTimer = setTimeout(async () => {
        try {
            tiktokConnection = new WebcastPushConnection(username);
            await tiktokConnection.connect();
            reconnectAttempts = 0;
            io.emit('tiktok_status', { success: true, message: `✅ تم إعادة الاتصال ببث: ${username}` });
            attachTikTokListeners(null, username, secretWord, reviveWord);
        } catch (err) {
            attemptReconnect(username, secretWord, reviveWord);
        }
    }, delayMs);
}

io.on('connection', (socket) => {
    console.log(`الواجهة اتصلت بالسيرفر بنجاح ✅ (المستخدم: ${socket.user?.displayName || socket.user?.openId || 'غير معروف'})`);

    socket.on('connect_tiktok', async (data) => {
        const { username, secretWord, reviveWord } = data;

        if (!username || !secretWord) {
            socket.emit('tiktok_status', { success: false, message: 'الرجاء إدخال اليوزر والكلمة السرية.' });
            return;
        }

        // منع فتح أكثر من اتصال بنفس الوقت
        await disconnectCurrent();
        reconnectAttempts = 0;
        currentUsername = username;

        tiktokConnection = new WebcastPushConnection(username);

        try {
            await tiktokConnection.connect();
            socket.emit('tiktok_status', { success: true, message: `✅ متصل ببث: ${username}` });
            attachTikTokListeners(socket, username, secretWord, reviveWord);
        } catch (err) {
            socket.emit('tiktok_status', { success: false, message: 'فشل الاتصال بالبث، تأكد أن البث لايف حالياً!' });
            tiktokConnection = null;
        }
    });

    socket.on('disconnect_tiktok', async () => {
        await disconnectCurrent();
        io.emit('tiktok_status', { success: false, message: 'تم قطع الاتصال بالبث يدوياً.' });
    });

    socket.on('disconnect', () => {
        console.log('واجهة انقطع اتصالها بالسيرفر');
    });
});

process.on('SIGINT', async () => {
    await disconnectCurrent();
    process.exit(0);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`السيرفر يعمل الآن على المنفذ Localhost:${PORT} 🚀`);
});
