/* Everlong access bot + login API
 * One Railway service: a Discord bot (whitelist accounts via /panel) + an Express login API.
 * Storage: Postgres (Railway "Add Postgres" auto-sets DATABASE_URL).
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const {
  Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder,
  ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder, PermissionFlagsBits
} = require('discord.js');

const {
  DISCORD_TOKEN, CLIENT_ID, GUILD_ID, WHITELIST_ROLE_ID,
  JWT_SECRET, DATABASE_URL, ALLOWED_ORIGIN
} = process.env;
const PORT = process.env.PORT || 3000;
const RESET_COOLDOWN_DAYS = Number(process.env.RESET_COOLDOWN_DAYS || 4);
const DAY = 86400000;

for (const k of ['DISCORD_TOKEN','CLIENT_ID','GUILD_ID','WHITELIST_ROLE_ID','JWT_SECRET','DATABASE_URL']) {
  if (!process.env[k]) console.warn('[warn] missing env var: ' + k);
}

/* ---------------- Database ---------------- */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false }
});
async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS accounts(
    discord_id    TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    session_token TEXT,
    created_at    TIMESTAMPTZ DEFAULT now(),
    last_reset_at TIMESTAMPTZ DEFAULT now()
  )`);
}

/* ---------------- Helpers ---------------- */
function genPassword(len = 12) {
  const cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; // no ambiguous chars
  const b = crypto.randomBytes(len);
  let s = '';
  for (let i = 0; i < len; i++) s += cs[b[i] % cs.length];
  return s;
}
function sanitize(name) {
  return (name || '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) || 'user';
}
async function uniqueUsername(base) {
  let u = sanitize(base);
  while ((await pool.query('SELECT 1 FROM accounts WHERE username=$1', [u])).rowCount) {
    u = sanitize(base) + '-' + crypto.randomBytes(2).toString('hex');
  }
  return u;
}

/* ---------------- Discord bot ---------------- */
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

const panelCmd = new SlashCommandBuilder()
  .setName('panel')
  .setDescription('Post the Everlong access panel in this channel')
  .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild);

async function registerCommands() {
  const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
  await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: [panelCmd.toJSON()] });
  console.log('Slash commands registered to guild ' + GUILD_ID);
}

function hasWhitelist(member) {
  return !!(member && member.roles && member.roles.cache && member.roles.cache.has(WHITELIST_ROLE_ID));
}
function isAdmin(interaction) {
  return interaction.memberPermissions && interaction.memberPermissions.has(PermissionFlagsBits.ManageGuild);
}

function panelEmbed() {
  return new EmbedBuilder()
    .setTitle('Everlong · Access')
    .setColor(0x101216)
    .setDescription(
      'Create your private login for the Everlong site.\n\n' +
      '• You need the **Whitelisted** role.\n' +
      '• One account per member (remembered).\n' +
      '• Your login activates on one device. To log in somewhere new, **Reset password** (once every ' + RESET_COOLDOWN_DAYS + ' days).'
    )
    .setFooter({ text: 'Your password is shown once — save it.' });
}
function panelButtons() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('el_create').setLabel('Create account').setStyle(ButtonStyle.Primary),
    new ButtonBuilder().setCustomId('el_reset').setLabel('Reset password').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('el_status').setLabel('My status').setStyle(ButtonStyle.Secondary)
  );
}

async function sendCreds(interaction, username, password, title) {
  const body =
    '**' + title + '**\nUse these to log in at the Everlong site:\n\n' +
    '**Username:** `' + username + '`\n' +
    '**Password:** `' + password + '`\n\n' +
    'Save them now — the password is only shown once. Logging in activates your account on one device; ' +
    'reset it here (every ' + RESET_COOLDOWN_DAYS + ' days) to log in somewhere new.';
  try {
    await interaction.user.send(body);
    await interaction.reply({ content: '✅ Sent your login to your DMs.', ephemeral: true });
  } catch (e) {
    await interaction.reply({ content: body + '\n\n*(I couldn’t DM you — showing it here privately. Enable DMs to receive it next time.)*', ephemeral: true });
  }
}

client.on('interactionCreate', async (i) => {
  try {
    if (i.isChatInputCommand() && i.commandName === 'panel') {
      if (!hasWhitelist(i.member) && !isAdmin(i)) {
        return i.reply({ content: 'You need the **Whitelisted** role (or Manage Server) to post the panel.', ephemeral: true });
      }
      await i.channel.send({ embeds: [panelEmbed()], components: [panelButtons()] });
      return i.reply({ content: 'Panel posted.', ephemeral: true });
    }

    if (i.isButton()) {
      if (!['el_create', 'el_reset', 'el_status'].includes(i.customId)) return;
      if (!hasWhitelist(i.member)) {
        return i.reply({ content: 'You need the **Whitelisted** role to do this.', ephemeral: true });
      }
      const did = i.user.id;
      const existing = await pool.query('SELECT * FROM accounts WHERE discord_id=$1', [did]);

      if (i.customId === 'el_status') {
        if (!existing.rowCount) return i.reply({ content: 'You don’t have an account yet. Press **Create account**.', ephemeral: true });
        const row = existing.rows[0];
        const nextTs = new Date(row.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * DAY;
        const can = Date.now() >= nextTs;
        const active = row.session_token ? 'Active on a device' : 'Not yet logged in';
        return i.reply({
          content:
            'Username: **' + row.username + '**\n' +
            'Status: ' + active + '\n' +
            'Reset available: ' + (can ? '**now**' : '<t:' + Math.floor(nextTs / 1000) + ':R>'),
          ephemeral: true
        });
      }

      if (i.customId === 'el_create') {
        if (existing.rowCount) {
          return i.reply({ content: 'You already have an account. Use **Reset password** to get new credentials.', ephemeral: true });
        }
        const username = await uniqueUsername(i.user.username || i.user.globalName || 'user');
        const password = genPassword();
        const hash = await bcrypt.hash(password, 10);
        await pool.query(
          'INSERT INTO accounts(discord_id, username, password_hash, session_token, last_reset_at) VALUES ($1,$2,$3,NULL,now())',
          [did, username, hash]
        );
        return sendCreds(i, username, password, 'Account created');
      }

      if (i.customId === 'el_reset') {
        if (!existing.rowCount) return i.reply({ content: 'You don’t have an account yet. Press **Create account**.', ephemeral: true });
        const row = existing.rows[0];
        const nextTs = new Date(row.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * DAY;
        if (Date.now() < nextTs) {
          return i.reply({ content: 'You can reset again <t:' + Math.floor(nextTs / 1000) + ':R>.', ephemeral: true });
        }
        const password = genPassword();
        const hash = await bcrypt.hash(password, 10);
        // clear session_token so the old device is logged out and the account can be re-activated
        await pool.query('UPDATE accounts SET password_hash=$1, session_token=NULL, last_reset_at=now() WHERE discord_id=$2', [hash, did]);
        return sendCreds(i, row.username, password, 'Password reset');
      }
    }
  } catch (err) {
    console.error('interaction error', err);
    if (i.isRepliable()) { try { await i.reply({ content: 'Something went wrong — try again in a moment.', ephemeral: true }); } catch (_) {} }
  }
});

client.once('ready', () => console.log('Discord bot online as ' + client.user.tag));

/* ---------------- Login API ---------------- */
const app = express();
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGIN ? ALLOWED_ORIGIN.split(',').map(s => s.trim()) : true }));

// tiny in-memory rate limit per IP (10 / minute on login)
const hits = {};
function rateLimited(ip) {
  const now = Date.now();
  hits[ip] = (hits[ip] || []).filter(t => now - t < 60000);
  if (hits[ip].length >= 10) return true;
  hits[ip].push(now);
  return false;
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/login', async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x').toString();
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many attempts — wait a minute.' });
  const username = (req.body && req.body.username || '').toString().toLowerCase().trim();
  const password = (req.body && req.body.password || '').toString();
  if (!username || !password) return res.status(400).json({ error: 'Enter a username and password.' });

  const r = await pool.query('SELECT * FROM accounts WHERE username=$1', [username]);
  if (!r.rowCount) return res.status(401).json({ error: 'Invalid login.' });
  const row = r.rows[0];
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid login.' });

  // single-activation: if already claimed, block until reset in Discord
  if (row.session_token) {
    return res.status(409).json({ error: 'This account is already in use. Reset it in the Everlong Discord to log in again.' });
  }
  const sid = crypto.randomBytes(16).toString('hex');
  await pool.query('UPDATE accounts SET session_token=$1 WHERE discord_id=$2', [sid, row.discord_id]);
  const token = jwt.sign({ sub: row.discord_id, u: row.username, st: sid }, JWT_SECRET, { expiresIn: '60d' });
  res.json({ token, username: row.username });
});

// verify the token AND that it still matches the active session (a reset invalidates old devices)
app.get('/api/verify', async (req, res) => {
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  let payload;
  try { payload = jwt.verify(auth, JWT_SECRET); }
  catch (e) { return res.status(401).json({ ok: false, error: 'expired' }); }
  try {
    const r = await pool.query('SELECT session_token, username FROM accounts WHERE discord_id=$1', [payload.sub]);
    if (!r.rowCount || r.rows[0].session_token !== payload.st) {
      return res.status(401).json({ ok: false, error: 'revoked' });
    }
    res.json({ ok: true, username: r.rows[0].username });
  } catch (e) {
    console.error('verify error', e);
    res.status(500).json({ ok: false });
  }
});

/* ---------------- Boot ---------------- */
(async () => {
  await initDb();
  app.listen(PORT, () => console.log('Login API listening on ' + PORT));
  await client.login(DISCORD_TOKEN);
  await registerCommands();
})().catch((e) => { console.error('fatal boot error', e); process.exit(1); });
