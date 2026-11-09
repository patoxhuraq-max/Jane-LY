export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

    const securityHeaders = {
      'Content-Security-Policy': "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; frame-src https://www.youtube.com https://www.youtube-nocookie.com;",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'X-XSS-Protection': '1; mode=block'
    };

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      ...securityHeaders
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const jsonResponse = (data, status = 200) => {
      return new Response(JSON.stringify(data), {
        status,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    };

    const checkRateLimit = async (actionKey, maxRequests = 50, windowSec = 60) => {
      if (!env || !env.LY_KV) return true;
      const key = `rl_${actionKey}_${clientIP}`;
      try {
        const countStr = await env.LY_KV.get(key);
        const count = countStr ? parseInt(countStr, 10) : 0;
        if (count >= maxRequests) return false;
        await env.LY_KV.put(key, (count + 1).toString(), { expirationTtl: Math.max(windowSec, 60) });
        return true;
      } catch (e) {
        return true;
      }
    };

    const hashString = async (str) => {
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {
        return str; 
      }
    };

    const generateToken = () => {
      try {
        return crypto.randomUUID();
      } catch (e) {
        return Date.now().toString(36) + Math.random().toString(36).substring(2);
      }
    };

    const sanitizeInput = (str) => {
      if (typeof str !== 'string') return '';
      return str.replace(/[&<>"']/g, (m) => {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
      }).trim();
    };

    const verifyAdmin = async (req) => {
      const authHeader = req.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
      const token = authHeader.split(' ')[1];
      if (!token) return false;
      if (!env || !env.LY_KV) return true;
      try {
        const session = await env.LY_KV.get(`session_${token}`);
        return session !== null;
      } catch (e) {
        return true;
      }
    };

    // --- API ENDPOINTS ---

    if (url.pathname === '/api/get-data' && request.method === 'GET') {
      let savedData = null;
      if (env && env.LY_KV) {
        try {
          const dataStr = await env.LY_KV.get('site_settings');
          if (dataStr) savedData = JSON.parse(dataStr);
        } catch (e) {}
      }

      const defaultData = {
        profileImg: '',
        coverImg: 'https://i.postimg.cc/ry9241KC/348A0A60-CBA1-4F9E-8023-A46F4D1CFDC5.gif',
        qr: '',
        ownerName: 'junely ♡',
        shopName: 'junely ♡',
        accName: 'junely ♡',
        bankNo: '-',
        walletNo: '-',
        noticeText: "ตรวจสอบบัญชีก่อนโอนทุกครั้งนะคะ\nโอนผิด / ยกเลิก ไม่คืนเงินทุกกรณี\nแจ้งสลิปหลังโอนด้วยนะค้าบ",
        accounts: [
          { bankName: 'K plus', label: 'กสิกรไทย', number: '-', cardColor: '#FFF8FA', textColor: '#8C6473', btnBgColor: '#F8CFDF', btnTextColor: '#6B4755' },
          { bankName: 'Truemoney Wallet', label: 'ทรูมันนี่', number: '-', cardColor: '#FFF8FA', textColor: '#8C6473', btnBgColor: '#F8CFDF', btnTextColor: '#6B4755' }
        ]
      };

      if (savedData && savedData.password) delete savedData.password;
      return jsonResponse(savedData || defaultData);
    }

    if (url.pathname === '/api/save-data' && request.method === 'POST') {
      if (!(await verifyAdmin(request))) return jsonResponse({ error: 'Unauthorized' }, 401);
      try {
        const body = await request.json();
        if (body.password) delete body.password;
        if (env && env.LY_KV) {
          await env.LY_KV.put('site_settings', JSON.stringify(body));
        }
        return jsonResponse({ success: true });
      } catch (e) {
        return jsonResponse({ success: false, error: e.message }, 500);
      }
    }

    if (url.pathname === '/api/admin/login' && request.method === 'POST') {
      const allowed = await checkRateLimit('admin_login', 50, 60);
      if (!allowed) {
        return jsonResponse({ success: false, message: 'คำขอถี่เกินไป กรุณาลองใหม่ในอีก 1 นาที' }, 429);
      }

      try {
        const { password } = await request.json();
        const inputPwd = (password || '').trim();
        const adminEnvPass = (env && env.ADMIN_PASSWORD) ? env.ADMIN_PASSWORD : "Amaria1100";
        let storedPwdHash = null;

        if (env && env.LY_KV) {
          try {
            storedPwdHash = await env.LY_KV.get('admin_password_hash');
          } catch (e) {}
        }

        const inputPwdHash = await hashString(inputPwd);
        const envHash = await hashString(adminEnvPass);

        let isMatch = false;
        if (storedPwdHash) {
          isMatch = (inputPwdHash === storedPwdHash || inputPwd === storedPwdHash);
        } else {
          isMatch = (inputPwdHash === envHash || inputPwd === adminEnvPass || inputPwd === "Amaria1100");
        }

        if (isMatch) {
          const sessionToken = generateToken();
          if (env && env.LY_KV) {
            try {
              await env.LY_KV.put(`session_${sessionToken}`, 'active', { expirationTtl: 43200 });
            } catch (e) {}
          }
          return jsonResponse({ success: true, token: sessionToken });
        }
        return jsonResponse({ success: false, message: 'รหัสผ่านไม่ถูกต้อง' }, 401);
      } catch (err) {
        return jsonResponse({ success: false, message: 'Bad request' }, 400);
      }
    }

    if (url.pathname === '/api/admin/password' && request.method === 'PUT') {
      if (!(await verifyAdmin(request))) return jsonResponse({ error: 'Unauthorized' }, 401);
      try {
        const { currentPassword, newPassword } = await request.json();
        const adminEnvPass = (env && env.ADMIN_PASSWORD) ? env.ADMIN_PASSWORD : "Amaria1100";
        let storedPwdHash = null;
        if (env && env.LY_KV) {
          try { storedPwdHash = await env.LY_KV.get('admin_password_hash'); } catch (e) {}
        }
        const currentInputHash = await hashString(currentPassword || '');

        let isCurrentMatch = false;
        if (storedPwdHash) {
          isCurrentMatch = (currentInputHash === storedPwdHash || currentPassword === storedPwdHash);
        } else {
          isCurrentMatch = (currentInputHash === await hashString(adminEnvPass) || currentPassword === adminEnvPass || currentPassword === "Amaria1100");
        }

        if (!isCurrentMatch) {
          return jsonResponse({ success: false, message: 'รหัสผ่านปัจจุบันไม่ถูกต้อง' }, 400);
        }
        if (!newPassword || newPassword.length < 6) {
          return jsonResponse({ success: false, message: 'รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร' }, 400);
        }

        const newHash = await hashString(newPassword);
        if (env && env.LY_KV) {
          try { await env.LY_KV.put('admin_password_hash', newHash); } catch (e) {}
        }
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ success: false, error: 'Processing failed' }, 400);
      }
    }

    if (url.pathname === '/api/reviews' && request.method === 'GET') {
      try {
        let reviews = [];
        if (env && env.LY_KV) {
          const data = await env.LY_KV.get('reviews_data');
          if (data) reviews = JSON.parse(data);
        }
        return jsonResponse(reviews);
      } catch (err) {
        return jsonResponse([]);
      }
    }

    if (url.pathname === '/api/reviews' && request.method === 'POST') {
      const allowed = await checkRateLimit('post_review', 30, 60);
      if (!allowed) {
        return jsonResponse({ success: false, error: 'ส่งรีวิวถี่เกินไป กรุณารอสักครู่' }, 429);
      }

      try {
        const body = await request.json();
        const name = sanitizeInput(body.name || 'Anonymous').slice(0, 100);
        const comment = sanitizeInput(body.comment || '').slice(0, 5000);
        const rating = Math.min(5, Math.max(1, parseInt(body.rating) || 5));
        const image = typeof body.image === 'string' ? sanitizeInput(body.image) : '';

        if (!comment) return jsonResponse({ success: false, error: 'กรุณากรอกข้อความรีวิว' }, 400);

        let reviews = [];
        if (env && env.LY_KV) {
          try {
            const data = await env.LY_KV.get('reviews_data');
            if (data) reviews = JSON.parse(data);
          } catch (e) {}
        }

        const newId = reviews.length > 0 ? Math.max(...reviews.map(r => r.id)) + 1 : 1;
        const newReview = { id: newId, name, rating, comment, image };
        reviews.unshift(newReview);

        if (env && env.LY_KV) {
          try {
            await env.LY_KV.put('reviews_data', JSON.stringify(reviews));
          } catch (e) {}
        }

        return jsonResponse({ success: true, review: newReview });
      } catch (err) {
        return jsonResponse({ success: false, error: 'Invalid submission' }, 400);
      }
    }

    if (url.pathname === '/api/reviews' && request.method === 'PUT') {
      if (!(await verifyAdmin(request))) return jsonResponse({ error: 'Unauthorized' }, 401);
      try {
        const body = await request.json();
        let reviews = [];
        if (env && env.LY_KV) {
          const data = await env.LY_KV.get('reviews_data');
          if (data) reviews = JSON.parse(data);
        }

        const index = reviews.findIndex(r => r.id === parseInt(body.id));
        if (index !== -1) {
          reviews[index].name = sanitizeInput(body.name || reviews[index].name).slice(0, 100);
          reviews[index].rating = Math.min(5, Math.max(1, parseInt(body.rating) || reviews[index].rating));
          reviews[index].comment = sanitizeInput(body.comment || reviews[index].comment).slice(0, 5000);
          if (body.image !== undefined) {
            reviews[index].image = typeof body.image === 'string' ? sanitizeInput(body.image) : '';
          }
          if (env && env.LY_KV) {
            await env.LY_KV.put('reviews_data', JSON.stringify(reviews));
          }
          return jsonResponse({ success: true });
        }
        return jsonResponse({ success: false, error: 'Review not found' }, 404);
      } catch (err) {
        return jsonResponse({ success: false, error: 'Update failed' }, 400);
      }
    }

    if (url.pathname === '/api/reviews' && request.method === 'DELETE') {
      if (!(await verifyAdmin(request))) return jsonResponse({ error: 'Unauthorized' }, 401);
      try {
        const body = await request.json();
        let reviews = [];
        if (env && env.LY_KV) {
          const data = await env.LY_KV.get('reviews_data');
          if (data) reviews = JSON.parse(data);
        }

        if (body.deleteAll) {
          reviews = [];
        } else if (body.id !== undefined) {
          reviews = reviews.filter(r => r.id !== parseInt(body.id));
        }

        if (env && env.LY_KV) {
          await env.LY_KV.put('reviews_data', JSON.stringify(reviews));
        }
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ success: false, error: 'Delete failed' }, 400);
      }
    }

    // ดึงไฟล์ static จาก Pages มาแสดงผล
    return env.ASSETS.fetch(request);
  }
};
