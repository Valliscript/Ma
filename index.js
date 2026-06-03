/* Everlong access bot + login API
 * One Railway service: a Discord bot (whitelist accounts, moderation) + an Express login API.
 * Storage: Postgres (Railway "Add Postgres" sets DATABASE_URL automatically).
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
  ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder, PermissionFlagsBits,
  ModalBuilder, TextInputBuilder, TextInputStyle
} = require('discord.js');

const {
  DISCORD_TOKEN, CLIENT_ID, GUILD_ID, WHITELIST_ROLE_ID,
  JWT_SECRET, DATABASE_URL, ALLOWED_ORIGIN
} = process.env;
const PORT = process.env.PORT || 3000;
const RESET_COOLDOWN_DAYS = Number(process.env.RESET_COOLDOWN_DAYS || 4);
const DAY = 86400000;
const ACCENT = 0xCDD2DB;

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
  // migrations for already-deployed databases
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`);
  // login audit log
  await pool.query(`CREATE TABLE IF NOT EXISTS login_log(
    id        SERIAL PRIMARY KEY,
    discord_id TEXT,
    username  TEXT,
    ip        TEXT,
    success   BOOLEAN,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
}

/* ---------------- Helpers ---------------- */
function sanitize(name) {
  return (name || '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) || 'user';
}
async function uniqueUsername(base) {
  let u = sanitize(base);
  while ((await pool.query('SELECT 1 FROM accounts WHERE username=$1', [u])).rowCount) {
    u = sanitize(base) + crypto.randomBytes(2).toString('hex');
  }
  return u;
}
function hasWhitelist(member) {
  return !!(member && member.roles && member.roles.cache && member.roles.cache.has(WHITELIST_ROLE_ID));
}
function isAdmin(interaction) {
  return interaction.memberPermissions &&
    (interaction.memberPermissions.has(PermissionFlagsBits.ManageGuild) ||
     interaction.memberPermissions.has(PermissionFlagsBits.Administrator));
}
function pwError(pw) {
  if (!pw || pw.length < 8) return 'Password must be at least 8 characters.';
  if (pw.length > 64) return 'Password is too long (max 64).';
  return null;
}

/* ---------------- Discord client ---------------- */
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

/* ----- slash command definitions ----- */
const commands = [
  new SlashCommandBuilder().setName('panel').setDescription('Post the Everlong access panel (admins only)')
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),
  new SlashCommandBuilder().setName('whitelist').setDescription('Give a member the Whitelisted role')
    .addUserOption(o => o.setName('user').setDescription('Member to whitelist').setRequired(true))
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),
  new SlashCommandBuilder().setName('ban').setDescription('Ban a member and revoke their site access')
    .addUserOption(o => o.setName('user').setDescription('Member to ban').setRequired(true))
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false))
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),
  new SlashCommandBuilder().setName('unban').setDescription('Unban a user and restore site eligibility')
    .addUserOption(o => o.setName('user').setDescription('User to unban').setRequired(true))
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),
  new SlashCommandBuilder().setName('removecooldown').setDescription("Clear a member's password-reset cooldown")
    .addUserOption(o => o.setName('user').setDescription('Member').setRequired(true))
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
].map(c => c.toJSON());

async function registerCommands() {
  const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
  await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
  console.log('Slash commands registered to guild ' + GUILD_ID);
}

/* ----- the panel ----- */
function panelEmbed() {
  return new EmbedBuilder()
    .setColor(ACCENT)
    .setAuthor({ name: 'EVERLONG' })
    .setTitle('Member Access')
    .setDescription(
      'Welcome â this is where you unlock your access to the Everlong site after your purchase.\n\n' +
      'Once you\u2019ve **purchased**, you\u2019ll receive the **Whitelisted** role. Then just use the buttons below.\n' +
      '\u200b'
    )
    .addFields(
      { name: '\uD83D\uDD11  Press "Create account"', value: 'To set your **own password** and get your login. Your username is made for you. One account per buyer.', inline: false },
      { name: '\u267B\uFE0F  Press "Reset password"', value: 'Forgot it, or logging in on a new device? Get a fresh password here \u2014 once every **' + RESET_COOLDOWN_DAYS + ' days**.', inline: false },
      { name: '\uD83D\uDD0D  Press "My status"', value: 'To check your username, whether you\u2019re logged in, and your next reset.', inline: false },
      { name: '\u200b', value: '\uD83D\uDED2 **No access yet?** Make your purchase first \u2014 you can use this panel once you\u2019ve bought and received the Whitelisted role.', inline: false }
    )
    .setFooter({ text: 'Your password is shown once \u2014 save it somewhere safe.' });
}
function panelButtons() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('el_create').setLabel('Create account').setEmoji('\uD83D\uDD11').setStyle(ButtonStyle.Success),
    new ButtonBuilder().setCustomId('el_reset').setLabel('Reset password').setEmoji('\u267B\uFE0F').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('el_status').setLabel('My status').setEmoji('\uD83D\uDD0D').setStyle(ButtonStyle.Secondary)
  );
}

function passwordModal(id, title, label) {
  return new ModalBuilder().setCustomId(id).setTitle(title).addComponents(
    new ActionRowBuilder().addComponents(
      new TextInputBuilder().setCustomId('pw').setLabel(label).setStyle(TextInputStyle.Short)
        .setMinLength(8).setMaxLength(64).setRequired(true).setPlaceholder('At least 8 characters')
    ),
    new ActionRowBuilder().addComponents(
      new TextInputBuilder().setCustomId('pw2').setLabel('Confirm password').setStyle(TextInputStyle.Short)
        .setMinLength(8).setMaxLength(64).setRequired(true).setPlaceholder('Type it again')
    )
  );
}

async function dmCreds(interaction, username, password, title) {
  const body =
    '**' + title + '**\nLog in at the Everlong site with:\n\n' +
    '**Username:** `' + username + '`\n' +
    '**Password:** `' + password + '`\n\n' +
    'Logging in activates your account on one device. To use a new device, **Reset password** here (every ' + RESET_COOLDOWN_DAYS + ' days).';
  try {
    await interaction.user.send(body);
    await interaction.reply({ content: '\u2705 Done â your username is `' + username + '`. I sent the details to your DMs.', ephemeral: true });
  } catch (e) {
    await interaction.reply({ content: body + '\n\n*(I couldn\u2019t DM you â here it is privately. Turn on DMs to receive it next time.)*', ephemeral: true });
  }
}

/* ---------------- Interactions ---------------- */
client.on('interactionCreate', async (i) => {
  try {
    /* ===== slash commands ===== */
    if (i.isChatInputCommand()) {
      if (!isAdmin(i)) return i.reply({ content: 'This command is for admins only.', ephemeral: true });

      if (i.commandName === 'panel') {
        await i.channel.send({ embeds: [panelEmbed()], components: [panelButtons()] });
        return i.reply({ content: 'Panel posted.', ephemeral: true });
      }

      if (i.commandName === 'whitelist') {
        const u = i.options.getUser('user');
        const m = await i.guild.members.fetch(u.id).catch(() => null);
        if (!m) return i.reply({ content: 'That user isn\u2019t in this server.', ephemeral: true });
        try { await m.roles.add(WHITELIST_ROLE_ID); }
        catch (e) { return i.reply({ content: 'Couldn\u2019t add the role â make sure my role is **above** the Whitelisted role and I have **Manage Roles**.', ephemeral: true }); }
        return i.reply({ content: '\u2705 Whitelisted <@' + u.id + '>.', ephemeral: true });
      }

      if (i.commandName === 'ban') {
        const u = i.options.getUser('user');
        const reason = i.options.getString('reason') || 'Banned by an admin';
        if (u.id === i.user.id) return i.reply({ content: 'You can\u2019t ban yourself.', ephemeral: true });
        if (u.id === client.user.id) return i.reply({ content: 'I can\u2019t ban myself.', ephemeral: true });
        const m = await i.guild.members.fetch(u.id).catch(() => null);
        if (m && (m.permissions.has(PermissionFlagsBits.ManageGuild) || m.permissions.has(PermissionFlagsBits.Administrator))) {
          return i.reply({ content: 'That user is an admin â I won\u2019t ban them.', ephemeral: true });
        }
        // revoke site access
        await pool.query('UPDATE accounts SET banned=true, session_token=NULL WHERE discord_id=$1', [u.id]);
        let notes = ['Site access revoked'];
        // remove whitelist role
        if (m) { try { await m.roles.remove(WHITELIST_ROLE_ID); notes.push('role removed'); } catch (e) {} }
        // discord ban
        try { await i.guild.members.ban(u.id, { reason }); notes.push('banned from server'); }
        catch (e) { notes.push('\u26a0\ufe0f could NOT ban from server (check my **Ban Members** permission & role position)'); }
        return i.reply({ content: '\uD83D\uDD28 <@' + u.id + '>: ' + notes.join(' \u00b7 ') + '.', ephemeral: true });
      }

      if (i.commandName === 'unban') {
        const u = i.options.getUser('user');
        await pool.query('UPDATE accounts SET banned=false WHERE discord_id=$1', [u.id]);
        let note = 'site eligibility restored';
        try { await i.guild.bans.remove(u.id); note += ' \u00b7 unbanned from server'; } catch (e) { note += ' \u00b7 (was not server-banned)'; }
        return i.reply({ content: '\u2705 <@' + u.id + '>: ' + note + '. They can create an account again once they have the Whitelisted role.', ephemeral: true });
      }

      if (i.commandName === 'removecooldown') {
        const u = i.options.getUser('user');
        const r = await pool.query("UPDATE accounts SET last_reset_at = now() - ($1 || ' days')::interval WHERE discord_id=$2 RETURNING username",
          [String(RESET_COOLDOWN_DAYS + 1), u.id]);
        if (!r.rowCount) return i.reply({ content: 'That user doesn\u2019t have an account.', ephemeral: true });
        return i.reply({ content: '\u2705 Reset cooldown cleared for <@' + u.id + '> (`' + r.rows[0].username + '`). They can reset now.', ephemeral: true });
      }
      return;
    }

    /* ===== buttons ===== */
    if (i.isButton()) {
      if (!['el_create', 'el_reset', 'el_status'].includes(i.customId)) return;
      if (!hasWhitelist(i.member)) return i.reply({ content: 'You need the **Whitelisted** role to do this.', ephemeral: true });

      const did = i.user.id;
      const existing = await pool.query('SELECT * FROM accounts WHERE discord_id=$1', [did]);
      const row = existing.rows[0];

      if (i.customId === 'el_status') {
        if (!row) return i.reply({ content: 'You don\u2019t have an account yet. Press **Create account**.', ephemeral: true });
        const nextTs = new Date(row.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * DAY;
        const can = Date.now() >= nextTs;
        const lines = [
          'Username: **' + row.username + '**',
          'Status: ' + (row.banned ? '\u26d4 banned' : (row.session_token ? '\uD83D\uDFE2 active on a device' : '\u26aa not logged in yet')),
          'Last login: ' + (row.last_login_at ? '<t:' + Math.floor(new Date(row.last_login_at).getTime() / 1000) + ':R>' : 'never'),
          'Reset available: ' + (can ? '**now**' : '<t:' + Math.floor(nextTs / 1000) + ':R>')
        ];
        return i.reply({ content: lines.join('\n'), ephemeral: true });
      }

      if (i.customId === 'el_create') {
        if (row && row.banned) return i.reply({ content: 'Your access has been revoked.', ephemeral: true });
        if (row) return i.reply({ content: 'You already have an account (`' + row.username + '`). Use **Reset password** for new credentials.', ephemeral: true });
        return i.showModal(passwordModal('el_create_modal', 'Create your account', 'Choose a password'));
      }

      if (i.customId === 'el_reset') {
        if (!row) return i.reply({ content: 'You don\u2019t have an account yet. Press **Create account**.', ephemeral: true });
        if (row.banned) return i.reply({ content: 'Your access has been revoked.', ephemeral: true });
        const nextTs = new Date(row.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * DAY;
        if (Date.now() < nextTs) return i.reply({ content: 'You can reset again <t:' + Math.floor(nextTs / 1000) + ':R>.', ephemeral: true });
        return i.showModal(passwordModal('el_reset_modal', 'Reset your password', 'Choose a new password'));
      }
    }

    /* ===== modal submissions ===== */
    if (i.isModalSubmit()) {
      if (!hasWhitelist(i.member)) return i.reply({ content: 'You need the **Whitelisted** role.', ephemeral: true });
      const pw = i.fields.getTextInputValue('pw');
      const pw2 = i.fields.getTextInputValue('pw2');
      if (pw !== pw2) return i.reply({ content: 'Those passwords didn\u2019t match â try the button again.', ephemeral: true });
      const bad = pwError(pw);
      if (bad) return i.reply({ content: bad, ephemeral: true });
      const did = i.user.id;
      const existing = await pool.query('SELECT * FROM accounts WHERE discord_id=$1', [did]);
      const row = existing.rows[0];
      const hash = await bcrypt.hash(pw, 10);

      if (i.customId === 'el_create_modal') {
        if (row && row.banned) return i.reply({ content: 'Your access has been revoked.', ephemeral: true });
        if (row) return i.reply({ content: 'You already have an account (`' + row.username + '`).', ephemeral: true });
        const username = await uniqueUsername(i.user.username || i.user.globalName || 'user');
        await pool.query('INSERT INTO accounts(discord_id, username, password_hash, session_token, last_reset_at) VALUES ($1,$2,$3,NULL,now())',
          [did, username, hash]);
        return dmCreds(i, username, pw, 'Account created');
      }

      if (i.customId === 'el_reset_modal') {
        if (!row) return i.reply({ content: 'You don\u2019t have an account yet.', ephemeral: true });
        if (row.banned) return i.reply({ content: 'Your access has been revoked.', ephemeral: true });
        const nextTs = new Date(row.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * DAY;
        if (Date.now() < nextTs) return i.reply({ content: 'You can reset again <t:' + Math.floor(nextTs / 1000) + ':R>.', ephemeral: true });
        await pool.query('UPDATE accounts SET password_hash=$1, session_token=NULL, last_reset_at=now() WHERE discord_id=$2', [hash, did]);
        return dmCreds(i, row.username, pw, 'Password reset');
      }
    }
  } catch (err) {
    console.error('interaction error', err);
    if (i.isRepliable()) { try { await i.reply({ content: 'Something went wrong â try again in a moment.', ephemeral: true }); } catch (_) {} }
  }
});

client.once('ready', () => console.log('Discord bot online as ' + client.user.tag));

/* ---------------- Login API ---------------- */
const app = express();
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGIN ? ALLOWED_ORIGIN.split(',').map(s => s.trim()) : true }));

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
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many attempts â wait a minute.' });
  const username = (req.body && req.body.username || '').toString().toLowerCase().trim();
  const password = (req.body && req.body.password || '').toString();
  if (!username || !password) return res.status(400).json({ error: 'Enter a username and password.' });

  const r = await pool.query('SELECT * FROM accounts WHERE username=$1', [username]);
  const row = r.rows[0];
  
  // log attempt
  const success = !!(row && !row.banned && await (async()=>{if(!row)return false;return await bcrypt.compare(password, row.password_hash)})());
  await pool.query('INSERT INTO login_log(discord_id, username, ip, success) VALUES($1,$2,$3,$4)',
    [row ? row.discord_id : null, username, ip, success]).catch(()=>{});
  
  if (!r.rowCount) return res.status(401).json({ error: 'Invalid login.' });
  if (row.banned) return res.status(403).json({ error: 'This account has been revoked.' });
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid login.' });
  if (row.session_token) return res.status(409).json({ error: 'This account is already in use. Reset it in the Everlong Discord to log in again.' });

  const sid = crypto.randomBytes(16).toString('hex');
  await pool.query('UPDATE accounts SET session_token=$1, last_login_at=now() WHERE discord_id=$2', [sid, row.discord_id]);
  const token = jwt.sign({ sub: row.discord_id, u: row.username, st: sid }, JWT_SECRET, { expiresIn: '60d' });
  res.json({ token, username: row.username });
});

app.get('/api/verify', async (req, res) => {
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  let payload;
  try { payload = jwt.verify(auth, JWT_SECRET); }
  catch (e) { return res.status(401).json({ ok: false, error: 'expired' }); }
  try {
    const r = await pool.query('SELECT session_token, username, banned FROM accounts WHERE discord_id=$1', [payload.sub]);
    if (!r.rowCount || r.rows[0].banned || r.rows[0].session_token !== payload.st) {
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
