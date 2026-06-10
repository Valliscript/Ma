
/* Everlong access bot + login API
 * One Railway service: Discord bot (buyer access, admin panel, tickets) + Express login API.
 * Storage: Postgres (Railway "Add Postgres" sets DATABASE_URL).
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
  ModalBuilder, TextInputBuilder, TextInputStyle, ChannelType,
  UserSelectMenuBuilder, ChannelSelectMenuBuilder, StringSelectMenuBuilder, AttachmentBuilder
} = require('discord.js');

const {
  DISCORD_TOKEN, CLIENT_ID, GUILD_ID, WHITELIST_ROLE_ID,
  JWT_SECRET, DATABASE_URL, ALLOWED_ORIGIN
} = process.env;
const PORT = process.env.PORT || 3000;
const RESET_COOLDOWN_DAYS = Number(process.env.RESET_COOLDOWN_DAYS || 4);
const ANNOUNCE_CHANNEL_ID = process.env.ANNOUNCE_CHANNEL_ID || '';
const WELCOME_CHANNEL_ID = process.env.WELCOME_CHANNEL_ID || '1511747348450119720';
const DAY = 86400000;
const ACCENT = 0xCDD2DB;
const ADMIN_COLOR = 0x0A0B0D;

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
    discord_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    session_token TEXT, created_at TIMESTAMPTZ DEFAULT now(), last_reset_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS perm BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS protocol BOOLEAN DEFAULT false`);
  await pool.query(`CREATE TABLE IF NOT EXISTS login_log(
    id SERIAL PRIMARY KEY, discord_id TEXT, username TEXT, ip TEXT, success BOOLEAN, created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS announcements(
    id SERIAL PRIMARY KEY, message TEXT NOT NULL, author TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS suggestions(
    id SERIAL PRIMARY KEY, discord_id TEXT, username TEXT, text TEXT NOT NULL,
    message_id TEXT, channel_id TEXT, status TEXT DEFAULT 'open', created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS suggestion_votes(
    suggestion_id INT, user_id TEXT, value INT, PRIMARY KEY(suggestion_id, user_id))`);
}
async function getSetting(k, fb) { const r = await pool.query('SELECT value FROM settings WHERE key=$1', [k]); return r.rowCount ? r.rows[0].value : fb; }
async function setSetting(k, v) { await pool.query('INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', [k, v]); }

/* ---------------- Helpers ---------------- */
function sanitize(n) { return (n || '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) || 'user'; }
async function uniqueUsername(base) {
  let u = sanitize(base);
  while ((await pool.query('SELECT 1 FROM accounts WHERE username=$1', [u])).rowCount) u = sanitize(base) + crypto.randomBytes(2).toString('hex');
  return u;
}
function hasWhitelist(m) { return !!(m && m.roles && m.roles.cache && m.roles.cache.has(WHITELIST_ROLE_ID)); }
function isAdmin(i) { return i.memberPermissions && i.memberPermissions.has(PermissionFlagsBits.Administrator); }
function pwError(pw) { if (!pw || pw.length < 8) return 'Password must be at least 8 characters.'; if (pw.length > 64) return 'Password is too long (max 64).'; return null; }

/* ---------------- Discord client ---------------- */
const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });

/* admin slash commands - everything else is buttons */
const commands = [
  new SlashCommandBuilder().setName('adminpanel').setDescription('Open the Everlong admin control panel')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
  new SlashCommandBuilder().setName('livetracker').setDescription('Post a live, self-updating tracker (members online + accounts)')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
  new SlashCommandBuilder().setName('protocol').setDescription('Enable or disable Protocol Builder access for an account (admin only)')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .addSubcommand(sc => sc.setName('on').setDescription('Enable the Protocol page for an account')
      .addStringOption(o => o.setName('username').setDescription('The site account username').setRequired(true)))
    .addSubcommand(sc => sc.setName('off').setDescription('Disable the Protocol page for an account')
      .addStringOption(o => o.setName('username').setDescription('The site account username').setRequired(true))),
  new SlashCommandBuilder().setName('whoami').setDescription('Show your own Everlong account status'),
  new SlashCommandBuilder().setName('status').setDescription('Check that the bot, login API and database are running (admin only)')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
].map(c => c.toJSON());

async function registerCommands() {
  const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
  await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
  console.log('Slash commands registered');
}

/* ----- member-facing access panel (for buyers) ----- */
const SITE_ICON = 'https://everlongsguide.netlify.app/assets/icon-512.png';

function accessEmbed() {
  return new EmbedBuilder()
    .setColor(ACCENT)
    .setAuthor({ name: 'EVERLONG | MEMBER ACCESS' })
    .setThumbnail(SITE_ICON)
    .setTitle('Your key to the system')
    .setDescription('Purchased access? Set up your private login below.\n\n> Requires the **Whitelisted** role - granted after purchase.')
    .addFields(
      { name: '🔑 Create', value: 'Set your password & get your login.', inline: true },
      { name: '🔄 Reset', value: 'New device | every ' + RESET_COOLDOWN_DAYS + 'd.', inline: true },
      { name: '🔍 Status', value: 'Check your account.', inline: true }
    )
    .setFooter({ text: 'everlongsguide.netlify.app | your password is shown once' });
}
function accessButtons() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('el_create').setLabel('Create account').setEmoji('\uD83D\uDD11').setStyle(ButtonStyle.Success),
    new ButtonBuilder().setCustomId('el_reset').setLabel('Reset password').setEmoji('\uD83D\uDD04').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('el_status').setLabel('My status').setEmoji('\uD83D\uDD0D').setStyle(ButtonStyle.Secondary)
  );
}
function ticketEmbed() {
  return new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG' }).setTitle('Purchase')
    .setDescription('Want in? Open a ticket and we\u2019ll get you set up.');
}
function ticketButton() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('el_ticket_open').setLabel('Open ticket to purchase').setEmoji('\uD83D\uDED2').setStyle(ButtonStyle.Success)
  );
}
function passwordModal(id, title, label) {
  return new ModalBuilder().setCustomId(id).setTitle(title).addComponents(
    new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('pw').setLabel(label).setStyle(TextInputStyle.Short).setMinLength(8).setMaxLength(64).setRequired(true).setPlaceholder('At least 8 characters')),
    new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('pw2').setLabel('Confirm password').setStyle(TextInputStyle.Short).setMinLength(8).setMaxLength(64).setRequired(true).setPlaceholder('Type it again'))
  );
}
async function dmCreds(i, username, password, title) {
  const body = '**' + title + '**\nLog in at the Everlong site with:\n\n**Username:** `' + username + '`\n**Password:** `' + password + '`\n\nLogging in activates your account on one device. New device? **Reset password** (every ' + RESET_COOLDOWN_DAYS + ' days).';
  try { await i.user.send(body); await i.reply({ content: '\u2705 Done - your username is `' + username + '`. Sent to your DMs.', ephemeral: true }); }
  catch (e) { await i.reply({ content: body + '\n\n*(Couldn\u2019t DM you - shown privately. Turn on DMs.)*', ephemeral: true }); }
}

/* ----- admin control panel ----- */
const PANEL_SECTIONS = {
  access:  { label: 'Access',     emoji: '\uD83D\uDD11', color: 0x1f7a4d, blurb: 'Whitelist, locks, cooldowns and protocol / permanent access.' },
  accounts:{ label: 'Accounts',   emoji: '\uD83D\uDC64', color: 0x4a5560, blurb: 'Look up, audit and manage member site accounts.' },
  mod:     { label: 'Moderation', emoji: '\uD83D\uDEA8', color: 0xb0413e, blurb: 'Ban, kick, timeout \u2014 and reverse each one.' },
  channel: { label: 'Channel',    emoji: '\uD83D\uDCDF', color: 0x3b6fb0, blurb: 'Lock, slowmode, purge and speak in this channel.' },
  content: { label: 'Content',    emoji: '\uD83D\uDCE3', color: 0x1f7a4d, blurb: 'Announcements, sale link and the public panels.' }
};

function btn(id, label, style) { return new ButtonBuilder().setCustomId(id).setLabel(label).setStyle(style); }

// tab row — one button per section, the active one highlighted (Primary)
function panelTabs(active) {
  const row = new ActionRowBuilder();
  Object.keys(PANEL_SECTIONS).forEach(function (k) {
    const s = PANEL_SECTIONS[k];
    row.addComponents(
      new ButtonBuilder().setCustomId('adm_tab:' + k).setLabel(s.label).setEmoji(s.emoji)
        .setStyle(k === active ? ButtonStyle.Primary : ButtonStyle.Secondary)
    );
  });
  return row;
}

// command buttons for each section (each enable has its disable)
function panelButtons(section) {
  const G = ButtonStyle.Success, S = ButtonStyle.Secondary, D = ButtonStyle.Danger, P = ButtonStyle.Primary;
  // icon helper — escaped unicode, single codepoint, no variation selectors
  function ib(id, label, style, emoji) {
    const b = new ButtonBuilder().setCustomId(id).setLabel(label).setStyle(style);
    if (emoji) b.setEmoji(emoji);
    return b;
  }
  const rows = [];
  if (section === 'access') {
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_whitelist', 'Whitelist', G, '\u2795'), ib('adm_unwhitelist', 'Unwhitelist', S, '\u2796')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_perm', 'Make permanent', G, '\u2795'), ib('adm_unperm', 'Remove permanent', S, '\u2796')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_protocol_on', 'Protocol on', G, '\u2795'), ib('adm_protocol_off', 'Protocol off', S, '\u2796')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_forceunlock', 'Force-unlock', G, '\uD83D\uDD13'), ib('adm_relock', 'Re-lock', S, '\uD83D\uDD12'),
      ib('adm_cooldown', 'Set cooldown', S, '\u23F3'), ib('adm_clearcooldown', 'Clear cooldown', G, '\u2705')));
  } else if (section === 'accounts') {
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_lookup', 'Lookup', P, '\uD83D\uDD0D'), ib('adm_stats', 'Stats', S, '\uD83D\uDCCA')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_logins', 'Recent logins', S, '\uD83D\uDD11'), ib('adm_inactive', 'Inactive list', S, '\uD83D\uDCA4')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_export', 'Export CSV', S, '\uD83D\uDCC4'), ib('adm_setchannel', 'Set channel', S, '\uD83D\uDCCC')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_wipe', 'Wipe account', D, '\uD83D\uDDD1')));
  } else if (section === 'mod') {
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_ban', 'Ban', D, '\uD83D\uDD28'), ib('adm_unban', 'Unban', S, '\uD83D\uDD01')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_timeout', 'Timeout', D, '\uD83D\uDD07'), ib('adm_untimeout', 'Untimeout', S, '\uD83D\uDD01')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_kick', 'Kick', D, '\uD83D\uDC62')));
  } else if (section === 'channel') {
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_lock', 'Lock', P, '\uD83D\uDD12'), ib('adm_unlock', 'Unlock', S, '\uD83D\uDD13')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_slowmode', 'Slowmode on', P, '\uD83D\uDC0C'), ib('adm_slowmode_off', 'Slowmode off', S, '\u26A1')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_say', 'Say', P, '\uD83D\uDCAC'), ib('adm_purge', 'Purge', D, '\uD83E\uDDF9')));
  } else if (section === 'content') {
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_announce', 'Announce', G, '\uD83D\uDCE2'), ib('adm_sale', 'Sale link', G, '\uD83D\uDCB0')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_postaccess', 'Access panel', S, '\uD83D\uDD11'), ib('adm_postticket', 'Ticket panel', S, '\uD83C\uDFAB')));
    rows.push(new ActionRowBuilder().addComponents(
      ib('adm_postsuggest', 'Suggestion panel', S, '\uD83D\uDCA1')));
  }
  return rows;
}

function adminPanel(section) {
  section = section || 'access';
  const meta = PANEL_SECTIONS[section];
  const emb = new EmbedBuilder()
    .setColor(meta.color)
    .setAuthor({ name: 'EVERLONG | ADMIN CONTROL PANEL' })
    .setThumbnail(SITE_ICON)
    .setTitle(meta.emoji + '  ' + meta.label)
    .setDescription(meta.blurb + '\n\nUse the tabs above to switch sections. Every action that turns something on has a matching off.')
    .setFooter({ text: 'Administrators only \u00b7 ' + meta.label });
  return { embeds: [emb], components: [panelTabs(section)].concat(panelButtons(section)) };
}
function userPicker(id, ph) { return new ActionRowBuilder().addComponents(new UserSelectMenuBuilder().setCustomId(id).setPlaceholder(ph).setMinValues(1).setMaxValues(1)); }
function channelPicker(id, ph) { return new ActionRowBuilder().addComponents(new ChannelSelectMenuBuilder().setCustomId(id).setPlaceholder(ph).addChannelTypes(ChannelType.GuildText).setMinValues(1).setMaxValues(1)); }
function timeoutDurations(uid) {
  return new ActionRowBuilder().addComponents(new StringSelectMenuBuilder().setCustomId('adm_timeout_dur:' + uid).setPlaceholder('Choose a duration').addOptions(
    { label: '60 seconds', value: '1' },
    { label: '5 minutes', value: '5' },
    { label: '10 minutes', value: '10' },
    { label: '1 hour', value: '60' },
    { label: '1 day', value: '1440' },
    { label: '1 week', value: '10080' }
  ));
}
function salePost() {
  const emb = new EmbedBuilder()
    .setColor(0xE6B325)
    .setAuthor({ name: 'EVERLONG' })
    .setThumbnail(SITE_ICON)
    .setTitle('Be yourself, or be someone better.')
    .setDescription('Everlong is the complete system - looksmaxxing, training, skin, diet and routine - in one private members site.\n\nTap below to see the program and get access.')
    .addFields(
      { name: 'What you get', value: 'The full guide | routine builder | targets & body-comp tools | progress photos | ongoing updates', inline: false }
    )
    .setFooter({ text: 'everlongsguide.netlify.app/join' });
  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setLabel('View the program').setEmoji('\uD83D\uDD17').setStyle(ButtonStyle.Link).setURL('https://everlongsguide.netlify.app/join'),
    new ButtonBuilder().setLabel('Member login').setStyle(ButtonStyle.Link).setURL('https://everlongsguide.netlify.app/')
  );
  return { embeds: [emb], components: [row] };
}

/* ----- suggestions board ----- */
function suggestPanel() {
  return {
    embeds: [new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG' }).setTitle('Suggestions')
      .setDescription('Got an idea? Submit it below - everyone can vote with \uD83D\uDC4D / \uD83D\uDC4E.')],
    components: [new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId('sug_open').setLabel('Make a suggestion').setEmoji('\uD83D\uDCA1').setStyle(ButtonStyle.Primary))]
  };
}
function suggestionMessage(id, username, text, up, down) {
  const score = up - down;
  return {
    embeds: [new EmbedBuilder().setColor(ACCENT).setAuthor({ name: '\uD83D\uDCA1 Suggestion' }).setDescription(text)
      .addFields({ name: 'Score', value: '\uD83D\uDC4D ' + up + '\u2003\uD83D\uDC4E ' + down + '\u2003(' + (score >= 0 ? '+' : '') + score + ')' })
      .setFooter({ text: '#' + id + ' | by ' + username })],
    components: [new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId('sugv:up:' + id).setLabel(String(up)).setEmoji('\uD83D\uDC4D').setStyle(ButtonStyle.Success),
      new ButtonBuilder().setCustomId('sugv:down:' + id).setLabel(String(down)).setEmoji('\uD83D\uDC4E').setStyle(ButtonStyle.Danger))]
  };
}
async function suggestionCounts(id) {
  const r = await pool.query('SELECT value, COUNT(*) c FROM suggestion_votes WHERE suggestion_id=$1 GROUP BY value', [id]);
  let up = 0, down = 0;
  r.rows.forEach(x => { if (Number(x.value) === 1) up = Number(x.c); else if (Number(x.value) === -1) down = Number(x.c); });
  return { up, down };
}

async function lockChannel(ch, lock) {
  const everyone = ch.guild.roles.everyone.id;
  if (lock) {
    await ch.permissionOverwrites.edit(everyone, {
      ViewChannel: true, AddReactions: true,
      SendMessages: false, SendMessagesInThreads: false,
      CreatePublicThreads: false, CreatePrivateThreads: false
    });
  } else {
    await ch.permissionOverwrites.edit(everyone, {
      AddReactions: null, SendMessages: null, SendMessagesInThreads: null,
      CreatePublicThreads: null, CreatePrivateThreads: null
    });
  }
}
async function doBan(guild, uid, reason) {
  const notes = [];
  await pool.query('UPDATE accounts SET banned=true, session_token=NULL WHERE discord_id=$1', [uid]);
  notes.push('site access revoked');
  const m = await guild.members.fetch(uid).catch(() => null);
  if (m) { try { await m.roles.remove(WHITELIST_ROLE_ID); notes.push('role removed'); } catch (e) {} }
  try { await guild.members.ban(uid, { reason }); notes.push('banned from server'); }
  catch (e) { notes.push('\u26a0\ufe0f could NOT server-ban (check my Ban Members perm & role position)'); }
  return notes;
}
async function postAnnouncement(msg, author) {
  await pool.query('INSERT INTO announcements(message, author) VALUES($1,$2)', [msg, author]);
  const chId = await getSetting('announce_channel_id', ANNOUNCE_CHANNEL_ID);
  if (!chId) return 'saved to the website (no announcement channel set)';
  try {
    const ch = await client.channels.fetch(chId);
    await ch.send({ embeds: [new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG | Update' }).setDescription(msg).setTimestamp(new Date())] });
    return 'posted to <#' + chId + '> and the website';
  } catch (e) { return 'saved to the website (couldn\u2019t post to the channel - check ID/permissions)'; }
}

async function adminStats(i) {
  const a = (await pool.query("SELECT count(*)::int total, count(*) filter (where session_token is not null)::int active, count(*) filter (where banned)::int banned, count(*) filter (where perm)::int perm FROM accounts")).rows[0];
  const today = (await pool.query("SELECT count(*) filter (where success)::int ok, count(*) filter (where not success)::int fail FROM login_log WHERE created_at > now() - interval '24 hours'")).rows[0];
  const sug = (await pool.query('SELECT count(*)::int c FROM suggestions')).rows[0];
  const emb = new EmbedBuilder().setColor(ADMIN_COLOR).setAuthor({ name: 'EVERLONG | STATS' }).setThumbnail(SITE_ICON).setTitle('At a glance')
    .addFields(
      { name: '\uD83D\uDC65 Accounts', value: String(a.total), inline: true },
      { name: '\uD83D\uDFE2 Logged in now', value: String(a.active), inline: true },
      { name: '\uD83D\uDD11 Permanent', value: String(a.perm), inline: true },
      { name: '\uD83D\uDD28 Banned', value: String(a.banned), inline: true },
      { name: '\uD83D\uDD11 Logins (24h)', value: today.ok + ' ok | ' + today.fail + ' failed', inline: true },
      { name: '\uD83D\uDCA1 Suggestions', value: String(sug.c), inline: true }
    ).setTimestamp(new Date());
  return i.reply({ embeds: [emb], ephemeral: true });
}

async function adminLogins(i) {
  const r = await pool.query('SELECT username, ip, success, created_at FROM login_log ORDER BY created_at DESC LIMIT 10');
  if (!r.rowCount) return i.reply({ content: 'No login attempts logged yet.', ephemeral: true });
  const lines = r.rows.map(x => (x.success ? '\u2705' : '\u274C') + ' `' + (x.username || '?') + '` - <t:' + Math.floor(new Date(x.created_at).getTime() / 1000) + ':R>');
  const emb = new EmbedBuilder().setColor(ADMIN_COLOR).setAuthor({ name: 'EVERLONG | RECENT LOGINS' }).setDescription(lines.join('\n')).setFooter({ text: 'Last 10 attempts' });
  return i.reply({ embeds: [emb], ephemeral: true });
}

async function adminInactive(i) {
  // accounts that have never logged in OR not in 14+ days
  const r = await pool.query("SELECT username, last_login_at FROM accounts WHERE last_login_at IS NULL OR last_login_at < now() - interval '14 days' ORDER BY last_login_at ASC NULLS FIRST LIMIT 25");
  if (!r.rowCount) return i.reply({ content: '\u2705 No inactive accounts \u2014 everyone logged in within the last 14 days.', ephemeral: true });
  const lines = r.rows.map(function (x) {
    return '\u2022 `' + x.username + '` \u2014 ' + (x.last_login_at ? 'last <t:' + Math.floor(new Date(x.last_login_at).getTime() / 1000) + ':R>' : 'never logged in');
  });
  const emb = new EmbedBuilder().setColor(ADMIN_COLOR).setAuthor({ name: 'EVERLONG | INACTIVE ACCOUNTS' })
    .setTitle('Inactive 14+ days').setDescription(lines.join('\n')).setFooter({ text: 'Up to 25 shown, oldest first' });
  return i.reply({ embeds: [emb], ephemeral: true });
}

async function adminExport(i) {
  const r = await pool.query('SELECT username, perm, protocol, banned, session_token, created_at, last_login_at FROM accounts ORDER BY created_at ASC');
  const head = 'username,type,protocol,banned,logged_in_now,created,last_login';
  const rows = r.rows.map(function (a) {
    return [
      a.username,
      a.perm ? 'permanent' : 'standard',
      a.protocol ? 'yes' : 'no',
      a.banned ? 'yes' : 'no',
      a.session_token ? 'yes' : 'no',
      a.created_at ? new Date(a.created_at).toISOString().slice(0, 10) : '',
      a.last_login_at ? new Date(a.last_login_at).toISOString().slice(0, 10) : 'never'
    ].join(',');
  });
  const csv = [head].concat(rows).join('\n');
  const buf = Buffer.from(csv, 'utf8');
  const file = new AttachmentBuilder(buf, { name: 'everlong-accounts.csv' });
  return i.reply({ content: '\uD83D\uDCC4 ' + r.rowCount + ' accounts exported.', files: [file], ephemeral: true });
}

/* ----- live tracker (self-updating embed) ----- */
async function buildTrackerEmbed() {
  let online = 0, members = 0, whitelisted = 0;
  try {
    const g = await client.guilds.fetch({ guild: GUILD_ID, withCounts: true });
    online = g.approximatePresenceCount || 0;
    members = g.approximateMemberCount || 0;
  } catch (e) {}
  try {
    const guild = await client.guilds.fetch(GUILD_ID);
    const all = await guild.members.fetch();
    whitelisted = all.filter(m => m.roles.cache.has(WHITELIST_ROLE_ID)).size;
  } catch (e) {}
  let accounts = 0, today = 0;
  try {
    accounts = (await pool.query('SELECT count(*)::int c FROM accounts')).rows[0].c;
    today = (await pool.query("SELECT count(*)::int c FROM accounts WHERE created_at > now() - interval '24 hours'")).rows[0].c;
  } catch (e) {}
  return new EmbedBuilder()
    .setColor(0x2ECC71)
    .setAuthor({ name: 'EVERLONG | LIVE' })
    .setThumbnail(SITE_ICON)
    .setTitle('Live tracker')
    .addFields(
      { name: '\uD83D\uDC65 Total Discord members', value: '**' + members + '**', inline: true },
      { name: '\uD83D\uDFE2 Members online', value: '**' + online + '**', inline: true },
      { name: '\u2705 Whitelisted members', value: '**' + whitelisted + '**', inline: true },
      { name: '\uD83D\uDD11 Accounts created', value: '**' + accounts + '**', inline: true },
      { name: '\uD83C\uDD95 New today', value: '**' + today + '**', inline: true }
    )
    .setFooter({ text: 'Updates every minute' })
    .setTimestamp(new Date());
}

async function updateTracker() {
  let chId, msgId;
  try { chId = await getSetting('tracker_channel_id', null); msgId = await getSetting('tracker_message_id', null); } catch (e) { return; }
  if (!chId || !msgId) return;
  try {
    const ch = await client.channels.fetch(chId);
    const msg = await ch.messages.fetch(msgId);
    await msg.edit({ embeds: [await buildTrackerEmbed()] });
  } catch (e) {
    // message/channel gone - stop tracking so we don't spam errors
    try { await setSetting('tracker_message_id', ''); } catch (_) {}
  }
}

let trackerTimer = null;
function startTrackerLoop() {
  if (trackerTimer) return;
  trackerTimer = setInterval(() => { updateTracker().catch(() => {}); }, 60000);
}

/* ---------------- Interactions ---------------- */
client.on('interactionCreate', async (i) => {
  try {
    /* ===== /protocol — admin grants page access to an account ===== */
    if (i.isChatInputCommand() && i.commandName === 'protocol') {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      const sub = i.options.getSubcommand();
      const on = sub === 'on';
      const uname = i.options.getString('username').toLowerCase().trim();
      const r = await pool.query('UPDATE accounts SET protocol=$1 WHERE lower(username)=$2 RETURNING username', [on, uname]);
      if (!r.rowCount) {
        return i.reply({ content: '\u26A0\uFE0F No account found with username `' + uname + '`. Usernames are lowercase, no spaces.', ephemeral: true });
      }
      return i.reply({
        content: (on ? '\uD83E\uDDEC Protocol page **enabled**' : '\uD83D\uDD12 Protocol page **disabled**') +
          ' for `' + r.rows[0].username + '`.' + (on ? ' Visible after their next refresh.' : ''),
        ephemeral: true
      });
    }

    if (i.isChatInputCommand() && i.commandName === 'whoami') {
      const r = await pool.query('SELECT username, perm, protocol, banned, session_token, last_login_at FROM accounts WHERE discord_id=$1', [i.user.id]);
      const member = await i.guild.members.fetch(i.user.id).catch(function () { return null; });
      const wl = hasWhitelist(member);
      if (!r.rowCount) {
        return i.reply({ content: 'You don\u2019t have a site account yet. ' + (wl ? 'Use the **Create account** button in the access panel.' : 'Get whitelisted first, then create one.'), ephemeral: true });
      }
      const a = r.rows[0];
      const emb = new EmbedBuilder().setColor(0x1f7a4d).setAuthor({ name: 'EVERLONG | YOUR ACCOUNT' })
        .setThumbnail(i.user.displayAvatarURL()).setTitle(a.username)
        .addFields(
          { name: 'Type', value: a.perm ? '\uD83D\uDD11 Permanent' : '\uD83D\uDC64 Standard', inline: true },
          { name: 'Whitelisted', value: wl ? '\u2705 Yes' : '\u274C No', inline: true },
          { name: 'Protocol page', value: a.protocol ? '\uD83E\uDDEC Enabled' : '\uD83D\uDD12 Locked', inline: true },
          { name: 'Logged in now', value: a.session_token ? '\uD83D\uDFE2 Yes' : '\u26AB No', inline: true },
          { name: 'Last login', value: a.last_login_at ? '<t:' + Math.floor(new Date(a.last_login_at).getTime() / 1000) + ':R>' : '\u2014', inline: true }
        ).setFooter({ text: a.banned ? 'This account is banned' : 'everlongsguide.netlify.app' });
      return i.reply({ embeds: [emb], ephemeral: true });
    }

    if (i.isChatInputCommand() && i.commandName === 'status') {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      let db = false, dbMs = 0;
      const t0 = Date.now();
      try { await pool.query('SELECT 1'); db = true; dbMs = Date.now() - t0; } catch (e) {}
      const emb = new EmbedBuilder().setColor(db ? 0x1f7a4d : 0xb0413e).setAuthor({ name: 'EVERLONG | SYSTEM STATUS' })
        .addFields(
          { name: 'Bot', value: '\uD83D\uDFE2 Online', inline: true },
          { name: 'Gateway ping', value: Math.max(0, Math.round(client.ws.ping)) + ' ms', inline: true },
          { name: 'Database', value: db ? '\uD83D\uDFE2 OK (' + dbMs + ' ms)' : '\uD83D\uDD34 Unreachable', inline: true },
          { name: 'Uptime', value: Math.floor(process.uptime() / 3600) + 'h ' + Math.floor((process.uptime() % 3600) / 60) + 'm', inline: true }
        ).setTimestamp(new Date());
      return i.reply({ embeds: [emb], ephemeral: true });
    }

    /* ===== /adminpanel ===== */
    if (i.isChatInputCommand() && i.commandName === 'adminpanel') {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      return i.reply(Object.assign({ ephemeral: true }, adminPanel()));
    }
    if (i.isChatInputCommand() && i.commandName === 'livetracker') {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      await i.reply({ content: 'Posting the live tracker here...', ephemeral: true });
      const msg = await i.channel.send({ embeds: [await buildTrackerEmbed()] });
      await setSetting('tracker_channel_id', i.channel.id);
      await setSetting('tracker_message_id', msg.id);
      startTrackerLoop();
      return i.editReply({ content: '\u2705 Live tracker posted - it refreshes every minute. Delete that message to stop it.' });
    }

    /* ===== admin buttons ===== */
    if (i.isButton() && i.customId.startsWith('adm_tab:')) {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      return i.update(adminPanel(i.customId.split(':')[1]));
    }

    if (i.isButton() && i.customId.startsWith('adm_')) {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      switch (i.customId) {
        case 'adm_whitelist': return i.reply({ content: 'Pick a member to **whitelist**:', components: [userPicker('adm_pick_whitelist', 'Member to whitelist')], ephemeral: true });
        case 'adm_ban': return i.reply({ content: 'Pick a member to **ban** (also revokes site access):', components: [userPicker('adm_pick_ban', 'Member to ban')], ephemeral: true });
        case 'adm_cooldown': return i.reply({ content: 'Pick a member to **set** a reset cooldown on (starts the clock now):', components: [userPicker('adm_pick_cooldown_set', 'Member')], ephemeral: true });
        case 'adm_clearcooldown': return i.reply({ content: 'Pick a member to **clear** the reset cooldown for:', components: [userPicker('adm_pick_cooldown', 'Member')], ephemeral: true });
        case 'adm_setchannel': return i.reply({ content: 'Pick the **announcement channel**:', components: [channelPicker('adm_pick_setchannel', 'Announcement channel')], ephemeral: true });
        case 'adm_lock': return i.reply({ content: 'Pick a channel to **lock** (view + react only):', components: [channelPicker('adm_pick_lock', 'Channel to lock')], ephemeral: true });
        case 'adm_unlock': return i.reply({ content: 'Pick a channel to **unlock**:', components: [channelPicker('adm_pick_unlock', 'Channel to unlock')], ephemeral: true });
        case 'adm_unban':
          return i.showModal(new ModalBuilder().setCustomId('adm_unban_modal').setTitle('Unban a user').addComponents(
            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('uid').setLabel('User ID to unban').setStyle(TextInputStyle.Short).setRequired(true).setPlaceholder('e.g. 1234567890'))));
        case 'adm_announce':
          return i.showModal(new ModalBuilder().setCustomId('adm_announce_modal').setTitle('Post an announcement').addComponents(
            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('msg').setLabel('Announcement message').setStyle(TextInputStyle.Paragraph).setRequired(true).setMaxLength(1500).setPlaceholder('What\u2019s new?'))));
        case 'adm_postaccess':
          await i.channel.send({ embeds: [accessEmbed()], components: [accessButtons()] });
          return i.reply({ content: '\u2705 Access panel posted here.', ephemeral: true });
        case 'adm_postticket':
          await i.channel.send({ embeds: [ticketEmbed()], components: [ticketButton()] });
          return i.reply({ content: '\u2705 Ticket panel posted here.', ephemeral: true });
        case 'adm_postsuggest':
          await i.channel.send(suggestPanel());
          return i.reply({ content: '\u2705 Suggestion panel posted here.', ephemeral: true });
        case 'adm_forceunlock':
          return i.reply({ content: 'Pick a member to **force-unlock** (clears their active session so they can log in again now):', components: [userPicker('adm_pick_forceunlock', 'Member to unlock')], ephemeral: true });
        case 'adm_relock':
          return i.reply({ content: 'Pick a member to **re-lock** (signs them out everywhere and re-applies the single-use lock):', components: [userPicker('adm_pick_relock', 'Member to re-lock')], ephemeral: true });
        case 'adm_unperm': {
          const pr = await pool.query('SELECT username, discord_id FROM accounts WHERE perm=true ORDER BY username ASC LIMIT 25');
          if (!pr.rowCount) return i.reply({ content: 'There are no permanent accounts right now.', ephemeral: true });
          const menu = new StringSelectMenuBuilder().setCustomId('adm_pick_unperm').setPlaceholder('Pick a permanent account to revoke').setMinValues(1).setMaxValues(1)
            .addOptions(pr.rows.map(function (a) { return { label: a.username, value: a.discord_id, description: 'Remove permanent status' }; }));
          return i.reply({ content: 'Select the **permanent account** to revoke (re-applies single-use lock + cooldown):', components: [new ActionRowBuilder().addComponents(menu)], ephemeral: true });
        }
        case 'adm_protocol_on':
          return i.reply({ content: 'Pick a member to **enable the Protocol page** for:', components: [userPicker('adm_pick_protocol_on', 'Member')], ephemeral: true });
        case 'adm_protocol_off':
          return i.reply({ content: 'Pick a member to **disable the Protocol page** for:', components: [userPicker('adm_pick_protocol_off', 'Member')], ephemeral: true });
        case 'adm_inactive':
          return adminInactive(i);
        case 'adm_export':
          return adminExport(i);
        case 'adm_slowmode_off':
          try { await i.channel.setRateLimitPerUser(0); return i.reply({ content: '\u2705 Slowmode turned **off** in this channel.', ephemeral: true }); }
          catch (e) { return i.reply({ content: '\u26A0\uFE0F Could not change slowmode here.', ephemeral: true }); }
        case 'adm_lookup':
          return i.reply({ content: 'Pick a member to **look up**:', components: [userPicker('adm_pick_lookup', 'Member')], ephemeral: true });
        case 'adm_wipe':
          return i.reply({ content: 'Pick a member whose account you want to **permanently delete**:', components: [userPicker('adm_pick_wipe', 'Member to wipe')], ephemeral: true });
        case 'adm_perm':
          return i.showModal(new ModalBuilder().setCustomId('adm_perm_modal').setTitle('Create a permanent account').addComponents(
            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('u').setLabel('Username').setStyle(TextInputStyle.Short).setRequired(true).setMinLength(3).setMaxLength(20).setPlaceholder('e.g. owner')),
            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('p').setLabel('Password (min 8 chars)').setStyle(TextInputStyle.Short).setRequired(true).setMinLength(8).setMaxLength(64).setPlaceholder('choose a strong password'))));
        case 'adm_stats':
          return adminStats(i);
        case 'adm_logins':
          return adminLogins(i);
        case 'adm_slowmode':
          return i.showModal(new ModalBuilder().setCustomId('adm_slowmode_modal').setTitle('Set slowmode (this channel)').addComponents(
            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('s').setLabel('Seconds between messages (0 = off)').setStyle(TextInputStyle.Short).setRequired(true).setMaxLength(5).setPlaceholder('0 - 21600'))));
        case 'adm_purge':
          return i.showModal(new ModalBuilder().setCustomId('adm_purge_modal').setTitle('Purge messages (this channel)').addComponents(
            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('n').setLabel('How many messages to delete?').setStyle(TextInputStyle.Short).setRequired(true).setMaxLength(3).setPlaceholder('1 - 100'))));
        case 'adm_unwhitelist':
          return i.reply({ content: 'Pick a member to **remove** the Whitelisted role from:', components: [userPicker('adm_pick_unwhitelist', 'Member to unwhitelist')], ephemeral: true });
        case 'adm_kick':
          return i.reply({ content: 'Pick a member to **kick** from the server:', components: [userPicker('adm_pick_kick', 'Member to kick')], ephemeral: true });
        case 'adm_timeout':
          return i.reply({ content: 'Pick a member to **time out** (mute):', components: [userPicker('adm_pick_timeout', 'Member to timeout')], ephemeral: true });
        case 'adm_untimeout':
          return i.reply({ content: 'Pick a member to **remove timeout** from:', components: [userPicker('adm_pick_untimeout', 'Member')], ephemeral: true });
        case 'adm_say':
          return i.showModal(new ModalBuilder().setCustomId('adm_say_modal').setTitle('Say something (this channel)').addComponents(
            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('m').setLabel('Message to post as the bot').setStyle(TextInputStyle.Paragraph).setRequired(true).setMaxLength(1800).setPlaceholder('Type your message...'))));
        case 'adm_sale':
          await i.channel.send(salePost());
          return i.reply({ content: '\u2705 Sale post sent here.', ephemeral: true });
      }
      return;
    }

    /* ===== admin user-select menus ===== */
    if (i.isUserSelectMenu() && i.customId.startsWith('adm_pick_')) {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      const uid = i.values[0];
      if (i.customId === 'adm_pick_whitelist') {
        const m = await i.guild.members.fetch(uid).catch(() => null);
        if (!m) return i.update({ content: 'That user isn\u2019t in this server.', components: [] });
        try { await m.roles.add(WHITELIST_ROLE_ID); } catch (e) { return i.update({ content: 'Couldn\u2019t add the role - my role must be **above** Whitelisted and I need **Manage Roles**.', components: [] }); }
        return i.update({ content: '\u2705 Whitelisted <@' + uid + '>.', components: [] });
      }
      if (i.customId === 'adm_pick_ban') {
        if (uid === i.user.id) return i.update({ content: 'You can\u2019t ban yourself.', components: [] });
        if (uid === client.user.id) return i.update({ content: 'I can\u2019t ban myself.', components: [] });
        const m = await i.guild.members.fetch(uid).catch(() => null);
        if (m && (m.permissions.has(PermissionFlagsBits.ManageGuild) || m.permissions.has(PermissionFlagsBits.Administrator)))
          return i.update({ content: 'That user is staff - I won\u2019t ban them.', components: [] });
        const notes = await doBan(i.guild, uid, 'Banned via admin panel');
        return i.update({ content: '\uD83D\uDD28 <@' + uid + '>: ' + notes.join(' | ') + '.', components: [] });
      }
      if (i.customId === 'adm_pick_cooldown') {
        const r = await pool.query("UPDATE accounts SET last_reset_at = now() - ($1 || ' days')::interval WHERE discord_id=$2 RETURNING username", [String(RESET_COOLDOWN_DAYS + 1), uid]);
        if (!r.rowCount) return i.update({ content: 'That user has no account.', components: [] });
        return i.update({ content: '\u2705 Cooldown cleared for <@' + uid + '> (`' + r.rows[0].username + '`).', components: [] });
      }
      if (i.customId === 'adm_pick_forceunlock') {
        const r = await pool.query('UPDATE accounts SET session_token=NULL WHERE discord_id=$1 RETURNING username', [uid]);
        if (!r.rowCount) return i.update({ content: 'That user has no account.', components: [] });
        return i.update({ content: '\uD83D\uDD13 Session cleared for <@' + uid + '> (`' + r.rows[0].username + '`). They can log in again right now.', components: [] });
      }
      if (i.customId === 'adm_pick_relock') {
        const r = await pool.query('UPDATE accounts SET session_token=NULL, last_reset_at=now() WHERE discord_id=$1 RETURNING username', [uid]);
        if (!r.rowCount) return i.update({ content: 'That user has no account.', components: [] });
        return i.update({ content: '\uD83D\uDD12 Re-locked <@' + uid + '> (`' + r.rows[0].username + '`). Signed out everywhere; single-use lock + cooldown re-applied.', components: [] });
      }
      if (i.customId === 'adm_pick_cooldown_set') {
        const r = await pool.query('UPDATE accounts SET last_reset_at=now() WHERE discord_id=$1 RETURNING username', [uid]);
        if (!r.rowCount) return i.update({ content: 'That user has no account.', components: [] });
        return i.update({ content: '\u23F3 Cooldown started for <@' + uid + '> (`' + r.rows[0].username + '`). They can reset again in ' + RESET_COOLDOWN_DAYS + ' days.', components: [] });
      }
      if (i.customId === 'adm_pick_protocol_on') {
        const r = await pool.query('UPDATE accounts SET protocol=true WHERE discord_id=$1 RETURNING username', [uid]);
        if (!r.rowCount) return i.update({ content: 'That user has no account.', components: [] });
        return i.update({ content: '\uD83E\uDDEC Protocol page **enabled** for <@' + uid + '> (`' + r.rows[0].username + '`). Visible after their next refresh.', components: [] });
      }
      if (i.customId === 'adm_pick_protocol_off') {
        const r = await pool.query('UPDATE accounts SET protocol=false WHERE discord_id=$1 RETURNING username', [uid]);
        if (!r.rowCount) return i.update({ content: 'That user has no account.', components: [] });
        return i.update({ content: '\uD83D\uDD12 Protocol page **disabled** for <@' + uid + '> (`' + r.rows[0].username + '`).', components: [] });
      }
      if (i.customId === 'adm_pick_lookup') {
        const r = await pool.query('SELECT username, banned, perm, protocol, session_token, created_at, last_login_at, last_reset_at FROM accounts WHERE discord_id=$1', [uid]);
        const member = await i.guild.members.fetch(uid).catch(() => null);
        const wl = hasWhitelist(member);

        if (!r.rowCount) {
          const emb0 = new EmbedBuilder().setColor(ADMIN_COLOR).setAuthor({ name: 'EVERLONG | ACCOUNT LOOKUP' })
            .setThumbnail(member ? member.user.displayAvatarURL() : SITE_ICON)
            .setTitle(member ? member.user.username : 'Unknown member')
            .setDescription('**No site account created yet.**')
            .addFields(
              { name: 'Discord', value: '<@' + uid + '>', inline: true },
              { name: 'Whitelisted', value: wl ? '\u2705 Yes' : '\u274C No', inline: true },
              { name: 'In server', value: member ? '\u2705 Yes' : '\u274C No', inline: true }
            ).setFooter({ text: 'User ID ' + uid });
          return i.update({ content: '', embeds: [emb0], components: [] });
        }

        const a = r.rows[0];
        const fmt = (d) => d ? '<t:' + Math.floor(new Date(d).getTime() / 1000) + ':R>' : '\u2014';
        const fmtFull = (d) => d ? '<t:' + Math.floor(new Date(d).getTime() / 1000) + ':f>' : '\u2014';

        const lg = await pool.query(
          'SELECT COUNT(*) FILTER (WHERE success) AS ok, COUNT(*) FILTER (WHERE NOT success) AS fail, COUNT(DISTINCT ip) FILTER (WHERE success) AS devices, MAX(created_at) FILTER (WHERE NOT success) AS last_fail FROM login_log WHERE discord_id=$1', [uid]);
        const stats = lg.rows[0] || {};

        let cooldown = 'No cooldown';
        if (!a.perm && a.last_reset_at) {
          const next = new Date(a.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * 86400000;
          cooldown = next > Date.now() ? 'Until <t:' + Math.floor(next / 1000) + ':R>' : '\u2705 Can reset now';
        } else if (a.perm) { cooldown = '\u221E None (perm)'; }

        const emb = new EmbedBuilder().setColor(ADMIN_COLOR).setAuthor({ name: 'EVERLONG | ACCOUNT LOOKUP' })
          .setThumbnail(member ? member.user.displayAvatarURL() : SITE_ICON)
          .setTitle(a.username)
          .setDescription('<@' + uid + '>' + (member ? '' : '  \u00b7  *left the server*'))
          .addFields(
            { name: 'Account type', value: a.perm ? '\uD83D\uDD11 Permanent' : '\uD83D\uDC64 Standard', inline: true },
            { name: 'Status', value: a.banned ? '\uD83D\uDD28 Banned' : '\u2705 Active', inline: true },
            { name: 'Whitelisted', value: wl ? '\u2705 Yes' : '\u274C No', inline: true },
            { name: 'Protocol page', value: a.protocol ? '\uD83E\uDDEC Enabled' : '\uD83D\uDD12 Locked', inline: true },
            { name: 'Logged in now', value: a.session_token ? '\uD83D\uDFE2 Yes' : '\u26AB No', inline: true },
            { name: 'Reset cooldown', value: cooldown, inline: true },
            { name: 'Created', value: fmtFull(a.created_at), inline: true },
            { name: 'Last login', value: fmt(a.last_login_at), inline: true },
            { name: 'Last reset', value: fmt(a.last_reset_at), inline: true },
            { name: 'Successful logins', value: String(stats.ok || 0), inline: true },
            { name: 'Failed attempts', value: String(stats.fail || 0) + (stats.last_fail ? ' (last ' + fmt(stats.last_fail) + ')' : ''), inline: true },
            { name: 'Devices seen', value: String(stats.devices || 0), inline: true }
          ).setFooter({ text: 'User ID ' + uid });
        return i.update({ content: '', embeds: [emb], components: [] });
      }
      if (i.customId === 'adm_pick_wipe') {
        const r = await pool.query('DELETE FROM accounts WHERE discord_id=$1 RETURNING username', [uid]);
        if (!r.rowCount) return i.update({ content: 'That user has no account to wipe.', components: [] });
        return i.update({ content: '\uD83D\uDDD1 Deleted the account `' + r.rows[0].username + '` for <@' + uid + '>. They can create a fresh one.', components: [] });
      }
      if (i.customId === 'adm_pick_unwhitelist') {
        const m = await i.guild.members.fetch(uid).catch(() => null);
        if (!m) return i.update({ content: 'That user isn\u2019t in this server.', components: [] });
        try { await m.roles.remove(WHITELIST_ROLE_ID); } catch (e) { return i.update({ content: 'Couldn\u2019t remove the role - my role must be above Whitelisted and I need Manage Roles.', components: [] }); }
        return i.update({ content: '\u2705 Removed Whitelisted from <@' + uid + '>.', components: [] });
      }
      if (i.customId === 'adm_pick_kick') {
        if (uid === i.user.id) return i.update({ content: 'You can\u2019t kick yourself.', components: [] });
        if (uid === client.user.id) return i.update({ content: 'I can\u2019t kick myself.', components: [] });
        const m = await i.guild.members.fetch(uid).catch(() => null);
        if (!m) return i.update({ content: 'That user isn\u2019t in this server.', components: [] });
        if (m.permissions.has(PermissionFlagsBits.ManageGuild) || m.permissions.has(PermissionFlagsBits.Administrator))
          return i.update({ content: 'That user is staff - I won\u2019t kick them.', components: [] });
        try { await m.kick('Kicked via admin panel'); } catch (e) { return i.update({ content: 'Couldn\u2019t kick - I need Kick Members and my role above theirs.', components: [] }); }
        return i.update({ content: '\uD83D\uDC62 Kicked <@' + uid + '>.', components: [] });
      }
      if (i.customId === 'adm_pick_timeout') {
        if (uid === i.user.id || uid === client.user.id) return i.update({ content: 'Pick someone else.', components: [] });
        return i.update({ content: 'How long should <@' + uid + '> be timed out?', components: [timeoutDurations(uid)] });
      }
      if (i.customId === 'adm_pick_untimeout') {
        const m = await i.guild.members.fetch(uid).catch(() => null);
        if (!m) return i.update({ content: 'That user isn\u2019t in this server.', components: [] });
        try { await m.timeout(null); } catch (e) { return i.update({ content: 'Couldn\u2019t lift it - I need Moderate Members.', components: [] }); }
        return i.update({ content: '\u2705 Timeout removed from <@' + uid + '>.', components: [] });
      }
      return;
    }

    /* ===== admin channel-select menus ===== */
    if (i.isChannelSelectMenu() && i.customId.startsWith('adm_pick_')) {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      const cid = i.values[0];
      const ch = i.guild.channels.cache.get(cid) || await i.guild.channels.fetch(cid).catch(() => null);
      if (i.customId === 'adm_pick_setchannel') { await setSetting('announce_channel_id', cid); return i.update({ content: '\u2705 Announcements will post to <#' + cid + '>.', components: [] }); }
      if (!ch) return i.update({ content: 'Couldn\u2019t find that channel.', components: [] });
      if (i.customId === 'adm_pick_lock') {
        try { await lockChannel(ch, true); return i.update({ content: '\uD83D\uDD12 <#' + cid + '> is now **view + react only** (no messages, no threads).', components: [] }); }
        catch (e) { return i.update({ content: 'Couldn\u2019t lock it - I need **Manage Channels** on that channel.', components: [] }); }
      }
      if (i.customId === 'adm_pick_unlock') {
        try { await lockChannel(ch, false); return i.update({ content: '\uD83D\uDD13 <#' + cid + '> unlocked.', components: [] }); }
        catch (e) { return i.update({ content: 'Couldn\u2019t unlock it - I need **Manage Channels** on that channel.', components: [] }); }
      }
      return;
    }

    /* ===== admin string-select menus ===== */
    if (i.isStringSelectMenu() && i.customId === 'adm_pick_unperm') {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      const uid = i.values[0];
      const r = await pool.query('UPDATE accounts SET perm=false, session_token=NULL, last_reset_at=now() WHERE discord_id=$1 RETURNING username', [uid]);
      if (!r.rowCount) return i.update({ content: 'That account no longer exists.', components: [] });
      return i.update({ content: '\u2705 Removed permanent status from `' + r.rows[0].username + '`. Standard rules (single-use lock + cooldown) now apply.', components: [] });
    }
    if (i.isStringSelectMenu() && i.customId.startsWith('adm_timeout_dur:')) {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      const uid = i.customId.split(':')[1];
      const mins = parseInt(i.values[0], 10);
      const m = await i.guild.members.fetch(uid).catch(() => null);
      if (!m) return i.update({ content: 'That user isn\u2019t in this server.', components: [] });
      if (m.permissions.has(PermissionFlagsBits.ManageGuild) || m.permissions.has(PermissionFlagsBits.Administrator))
        return i.update({ content: 'That user is staff - I won\u2019t time them out.', components: [] });
      try { await m.timeout(mins * 60000, 'Timed out via admin panel'); }
      catch (e) { return i.update({ content: 'Couldn\u2019t time them out - I need Moderate Members and my role above theirs.', components: [] }); }
      const label = mins >= 1440 ? (mins / 1440) + ' day(s)' : mins >= 60 ? (mins / 60) + ' hour(s)' : mins + ' minute(s)';
      return i.update({ content: '\u2705 <@' + uid + '> timed out for ' + label + '.', components: [] });
    }

    /* ===== member buttons ===== */
    if (i.isButton()) {
      // purchase tickets (open to everyone)
      if (i.customId === 'el_ticket_open') {
        const existing = i.guild.channels.cache.find(c => c.topic === 'ticket:' + i.user.id);
        if (existing) return i.reply({ content: 'You already have an open ticket: <#' + existing.id + '>.', ephemeral: true });
        try {
          const ch = await i.guild.channels.create({
            name: 'ticket-' + sanitize(i.user.username || 'buyer'),
            type: ChannelType.GuildText, topic: 'ticket:' + i.user.id,
            permissionOverwrites: [
              { id: i.guild.id, deny: [PermissionFlagsBits.ViewChannel] },
              { id: i.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] },
              { id: client.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.ManageChannels] }
            ]
          });
          const row = new ActionRowBuilder().addComponents(new ButtonBuilder().setCustomId('el_ticket_close').setLabel('Close ticket').setEmoji('\uD83D\uDD12').setStyle(ButtonStyle.Danger));
          await ch.send({ content: '<@' + i.user.id + '>', embeds: [new EmbedBuilder().setColor(ACCENT).setTitle('\uD83D\uDED2 Purchase ticket').setDescription('Thanks for your interest! A team member will be with you shortly. Tell us what you\u2019re after.')], components: [row] });
          return i.reply({ content: '\u2705 Ticket opened: <#' + ch.id + '>', ephemeral: true });
        } catch (e) { console.error('ticket create', e); return i.reply({ content: 'Couldn\u2019t open a ticket - I need **Manage Channels**.', ephemeral: true }); }
      }
      if (i.customId === 'el_ticket_close') {
        const isOwner = i.channel.topic === 'ticket:' + i.user.id;
        if (!isOwner && !isAdmin(i)) return i.reply({ content: 'Only the ticket owner or an admin can close this.', ephemeral: true });
        await i.reply({ content: 'Closing in 5 seconds\u2026' });
        setTimeout(() => { i.channel.delete().catch(() => {}); }, 5000);
        return;
      }

      // suggestions (open to everyone)
      if (i.customId === 'sug_open') {
        return i.showModal(new ModalBuilder().setCustomId('sug_modal').setTitle('Make a suggestion').addComponents(
          new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('text').setLabel('Your suggestion').setStyle(TextInputStyle.Paragraph).setRequired(true).setMaxLength(1000).setPlaceholder('What should we add or change?'))));
      }
      if (i.customId.startsWith('sugv:')) {
        const parts = i.customId.split(':');
        const val = parts[1] === 'up' ? 1 : -1;
        const id = parseInt(parts[2], 10);
        const ex = await pool.query('SELECT value FROM suggestion_votes WHERE suggestion_id=$1 AND user_id=$2', [id, i.user.id]);
        if (ex.rowCount && Number(ex.rows[0].value) === val) {
          await pool.query('DELETE FROM suggestion_votes WHERE suggestion_id=$1 AND user_id=$2', [id, i.user.id]);
        } else {
          await pool.query('INSERT INTO suggestion_votes(suggestion_id,user_id,value) VALUES($1,$2,$3) ON CONFLICT (suggestion_id,user_id) DO UPDATE SET value=$3', [id, i.user.id, val]);
        }
        const { up, down } = await suggestionCounts(id);
        const s = (await pool.query('SELECT username, text FROM suggestions WHERE id=$1', [id])).rows[0] || { username: '?', text: '' };
        return i.update(suggestionMessage(id, s.username, s.text, up, down));
      }

      // account buttons (whitelisted buyers only)
      if (!['el_create', 'el_reset', 'el_status'].includes(i.customId)) return;
      if (!hasWhitelist(i.member)) return i.reply({ content: 'You need the **Whitelisted** role to do this.', ephemeral: true });
      const did = i.user.id;
      const row = (await pool.query('SELECT * FROM accounts WHERE discord_id=$1', [did])).rows[0];

      if (i.customId === 'el_status') {
        if (!row) return i.reply({ content: 'No account yet. Press **Create account**.', ephemeral: true });
        const nextTs = new Date(row.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * DAY;
        return i.reply({ content: [
          'Username: **' + row.username + '**',
          'Status: ' + (row.banned ? '\u26d4 banned' : (row.session_token ? '\uD83D\uDFE2 active on a device' : '\u26aa not logged in yet')),
          'Last login: ' + (row.last_login_at ? '<t:' + Math.floor(new Date(row.last_login_at).getTime() / 1000) + ':R>' : 'never'),
          'Reset available: ' + (Date.now() >= nextTs ? '**now**' : '<t:' + Math.floor(nextTs / 1000) + ':R>')
        ].join('\n'), ephemeral: true });
      }
      if (i.customId === 'el_create') {
        if (row && row.banned) return i.reply({ content: 'Your access has been revoked.', ephemeral: true });
        if (row) return i.reply({ content: 'You already have an account (`' + row.username + '`). Use **Reset password**.', ephemeral: true });
        return i.showModal(passwordModal('el_create_modal', 'Create your account', 'Choose a password'));
      }
      if (i.customId === 'el_reset') {
        if (!row) return i.reply({ content: 'No account yet. Press **Create account**.', ephemeral: true });
        if (row.banned) return i.reply({ content: 'Your access has been revoked.', ephemeral: true });
        const nextTs = new Date(row.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * DAY;
        if (Date.now() < nextTs) return i.reply({ content: 'You can reset again <t:' + Math.floor(nextTs / 1000) + ':R>.', ephemeral: true });
        return i.showModal(passwordModal('el_reset_modal', 'Reset your password', 'Choose a new password'));
      }
      return;
    }

    /* ===== modals ===== */
    if (i.isModalSubmit()) {
      // suggestions (everyone)
      if (i.customId === 'sug_modal') {
        const text = i.fields.getTextInputValue('text');
        const r = await pool.query('INSERT INTO suggestions(discord_id, username, text) VALUES($1,$2,$3) RETURNING id', [i.user.id, i.user.username, text]);
        const id = r.rows[0].id;
        const msg = await i.channel.send(suggestionMessage(id, i.user.username, text, 0, 0));
        await pool.query('UPDATE suggestions SET message_id=$1, channel_id=$2 WHERE id=$3', [msg.id, i.channel.id, id]);
        return i.reply({ content: '\u2705 Suggestion posted! Others can vote on it now.', ephemeral: true });
      }
      // admin: announcement
      if (i.customId === 'adm_announce_modal') {
        if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
        const msg = i.fields.getTextInputValue('msg');
        const note = await postAnnouncement(msg, i.user.username);
        return i.reply({ content: '\uD83D\uDCE2 Announcement ' + note + '.', ephemeral: true });
      }
      // admin: unban
      if (i.customId === 'adm_unban_modal') {
        if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
        const uid = i.fields.getTextInputValue('uid').trim();
        if (!/^\d{5,25}$/.test(uid)) return i.reply({ content: 'That doesn\u2019t look like a valid user ID.', ephemeral: true });
        await pool.query('UPDATE accounts SET banned=false WHERE discord_id=$1', [uid]);
        let note = 'site eligibility restored';
        try { await i.guild.bans.remove(uid); note += ' | unbanned from server'; } catch (e) { note += ' | (was not server-banned)'; }
        return i.reply({ content: '\u2705 <@' + uid + '>: ' + note + '.', ephemeral: true });
      }
      // admin: create permanent account
      if (i.customId === 'adm_perm_modal') {
        if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
        const u = i.fields.getTextInputValue('u').trim().toLowerCase();
        const p = i.fields.getTextInputValue('p');
        if (!/^[a-z0-9_]{3,20}$/.test(u)) return i.reply({ content: 'Username must be 3\u201320 chars: letters, numbers, underscores.', ephemeral: true });
        const bad = pwError(p); if (bad) return i.reply({ content: bad, ephemeral: true });
        const taken = (await pool.query('SELECT 1 FROM accounts WHERE lower(username)=$1', [u])).rowCount;
        if (taken) return i.reply({ content: 'That username is already taken - pick another.', ephemeral: true });
        const hash = await bcrypt.hash(p, 10);
        const did = 'perm-' + crypto.randomBytes(8).toString('hex');
        await pool.query('INSERT INTO accounts(discord_id, username, password_hash, session_token, last_reset_at, perm) VALUES ($1,$2,$3,NULL,now(),true)', [did, u, hash]);
        const emb = new EmbedBuilder().setColor(ADMIN_COLOR).setAuthor({ name: 'EVERLONG | PERMANENT ACCOUNT' }).setThumbnail(SITE_ICON)
          .setTitle('Account ready')
          .setDescription('Log in and out as much as you want - **no single-use lock, no cooldown**, multiple devices fine.')
          .addFields(
            { name: 'Username', value: '`' + u + '`', inline: true },
            { name: 'Password', value: '`' + p + '`', inline: true },
            { name: 'Login', value: 'everlongsguide.netlify.app', inline: false }
          ).setFooter({ text: 'Save these - shown once here. Username is lowercase.' });
        return i.reply({ embeds: [emb], ephemeral: true });
      }
      // admin: slowmode (this channel)
      if (i.customId === 'adm_slowmode_modal') {
        if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
        let s = parseInt(i.fields.getTextInputValue('s').trim(), 10);
        if (!Number.isFinite(s) || s < 0 || s > 21600) return i.reply({ content: 'Enter a number of seconds between 0 and 21600.', ephemeral: true });
        try { await i.channel.setRateLimitPerUser(s); }
        catch (e) { return i.reply({ content: 'Couldn\u2019t set slowmode - I need **Manage Channels** here.', ephemeral: true }); }
        return i.reply({ content: s === 0 ? '\u2705 Slowmode turned off in this channel.' : '\u2705 Slowmode set to **' + s + 's** in this channel.', ephemeral: true });
      }
      // admin: purge (this channel)
      if (i.customId === 'adm_purge_modal') {
        if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
        let n = parseInt(i.fields.getTextInputValue('n').trim(), 10);
        if (!Number.isFinite(n) || n < 1 || n > 100) return i.reply({ content: 'Enter a number between 1 and 100.', ephemeral: true });
        try {
          const del = await i.channel.bulkDelete(n, true);
          return i.reply({ content: '\uD83E\uDDF9 Deleted **' + del.size + '** message(s). (Messages older than 14 days can\u2019t be bulk-deleted.)', ephemeral: true });
        } catch (e) { return i.reply({ content: 'Couldn\u2019t purge - I need **Manage Messages** here.', ephemeral: true }); }
      }
      // admin: say (post as the bot in this channel)
      if (i.customId === 'adm_say_modal') {
        if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
        const m = i.fields.getTextInputValue('m');
        try { await i.channel.send({ content: m, allowedMentions: { parse: [] } }); }
        catch (e) { return i.reply({ content: 'Couldn\u2019t post - I need Send Messages here.', ephemeral: true }); }
        return i.reply({ content: '\u2705 Posted.', ephemeral: true });
      }
      // member: create / reset
      if (i.customId === 'el_create_modal' || i.customId === 'el_reset_modal') {
        if (!hasWhitelist(i.member)) return i.reply({ content: 'You need the **Whitelisted** role.', ephemeral: true });
        const pw = i.fields.getTextInputValue('pw'), pw2 = i.fields.getTextInputValue('pw2');
        if (pw !== pw2) return i.reply({ content: 'Those passwords didn\u2019t match - try the button again.', ephemeral: true });
        const bad = pwError(pw); if (bad) return i.reply({ content: bad, ephemeral: true });
        const did = i.user.id;
        const row = (await pool.query('SELECT * FROM accounts WHERE discord_id=$1', [did])).rows[0];
        const hash = await bcrypt.hash(pw, 10);
        if (i.customId === 'el_create_modal') {
          if (row && row.banned) return i.reply({ content: 'Your access has been revoked.', ephemeral: true });
          if (row) return i.reply({ content: 'You already have an account (`' + row.username + '`).', ephemeral: true });
          const username = await uniqueUsername(i.user.username || i.user.globalName || 'user');
          await pool.query('INSERT INTO accounts(discord_id, username, password_hash, session_token, last_reset_at) VALUES ($1,$2,$3,NULL,now())', [did, username, hash]);
          return dmCreds(i, username, pw, 'Account created');
        } else {
          if (!row) return i.reply({ content: 'No account yet.', ephemeral: true });
          if (row.banned) return i.reply({ content: 'Your access has been revoked.', ephemeral: true });
          const nextTs = new Date(row.last_reset_at).getTime() + RESET_COOLDOWN_DAYS * DAY;
          if (Date.now() < nextTs) return i.reply({ content: 'You can reset again <t:' + Math.floor(nextTs / 1000) + ':R>.', ephemeral: true });
          await pool.query('UPDATE accounts SET password_hash=$1, session_token=NULL, last_reset_at=now() WHERE discord_id=$2', [hash, did]);
          return dmCreds(i, row.username, pw, 'Password reset');
        }
      }
    }
  } catch (err) {
    console.error('interaction error', err);
    if (i.isRepliable()) { try { await i.reply({ content: 'Something went wrong - try again.', ephemeral: true }); } catch (_) {} }
  }
});

/* ----- welcomer: greet new members ----- */
client.on('guildMemberAdd', async (member) => {
  try {
    if (member.user && member.user.bot) return;                 // welcome people, not bots
    if (GUILD_ID && member.guild.id !== GUILD_ID) return;        // only the Everlong server
    const chId = await getSetting('welcome_channel_id', WELCOME_CHANNEL_ID);
    if (!chId) return;
    const ch = await client.channels.fetch(chId).catch(() => null);
    if (!ch) return;
    const emb = new EmbedBuilder()
      .setColor(ACCENT)
      .setAuthor({ name: 'EVERLONG' })
      .setThumbnail(member.user.displayAvatarURL({ size: 256 }))
      .setTitle('Welcome to Everlong')
      .setDescription('You made it.\n\n> *Be yourself, or be someone better.*\n\nBought access? Open the member access panel to set up your private login. Just here to look? Start with the program below.')
      .setFooter({ text: 'Member #' + member.guild.memberCount + ' \u2022 everlongsguide.netlify.app' })
      .setTimestamp(new Date());
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setLabel('View the program').setEmoji('\uD83D\uDD17').setStyle(ButtonStyle.Link).setURL('https://everlongsguide.netlify.app/join'),
      new ButtonBuilder().setLabel('Member login').setStyle(ButtonStyle.Link).setURL('https://everlongsguide.netlify.app/')
    );
    await ch.send({ content: '<@' + member.id + '>', embeds: [emb], components: [row] });
  } catch (e) { console.error('welcome error', e); }
});

client.once('ready', () => console.log('Discord bot online as ' + client.user.tag));
client.on('error', (e) => console.error('client error', e));
process.on('unhandledRejection', (e) => console.error('unhandledRejection', e));
process.on('uncaughtException', (e) => console.error('uncaughtException', e));

/* ---------------- Login API ---------------- */
const app = express();
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGIN ? ALLOWED_ORIGIN.split(',').map(s => s.trim()) : true }));
const hits = {};
function rateLimited(ip) { const now = Date.now(); hits[ip] = (hits[ip] || []).filter(t => now - t < 60000); if (hits[ip].length >= 10) return true; hits[ip].push(now); return false; }

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/announcements', async (req, res) => {
  try { const r = await pool.query('SELECT message, created_at FROM announcements ORDER BY created_at DESC LIMIT 15'); res.json({ announcements: r.rows }); }
  catch (e) { res.json({ announcements: [] }); }
});
app.post('/api/login', async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x').toString();
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many attempts - wait a minute.' });
  const username = (req.body && req.body.username || '').toString().toLowerCase().trim();
  const password = (req.body && req.body.password || '').toString();
  if (!username || !password) return res.status(400).json({ error: 'Enter a username and password.' });
  const r = await pool.query('SELECT * FROM accounts WHERE lower(username)=$1', [username]);
  const row = r.rows[0];
  const success = !!(row && !row.banned && await (async () => { if (!row) return false; return await bcrypt.compare(password, row.password_hash); })());
  await pool.query('INSERT INTO login_log(discord_id, username, ip, success) VALUES($1,$2,$3,$4)', [row ? row.discord_id : null, username, ip, success]).catch(() => {});
  if (!r.rowCount) return res.status(401).json({ error: 'Invalid login.' });
  if (row.banned) return res.status(403).json({ error: 'This account has been revoked.' });
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid login.' });
  if (row.session_token && !row.perm) return res.status(409).json({ error: 'This account is already in use. Reset it in the Everlong Discord to log in again.' });
  const sid = crypto.randomBytes(16).toString('hex');
  await pool.query('UPDATE accounts SET session_token=$1, last_login_at=now() WHERE discord_id=$2', [sid, row.discord_id]);
  const token = jwt.sign({ sub: row.discord_id, u: row.username, st: sid, protocol: !!row.protocol }, JWT_SECRET, { expiresIn: '60d' });
  res.json({ token, username: row.username, protocol: !!row.protocol });
});
app.get('/api/verify', async (req, res) => {
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  let payload;
  try { payload = jwt.verify(auth, JWT_SECRET); } catch (e) { return res.status(401).json({ ok: false, error: 'expired' }); }
  try {
    const r = await pool.query('SELECT session_token, username, banned, perm, protocol FROM accounts WHERE discord_id=$1', [payload.sub]);
    if (!r.rowCount || r.rows[0].banned) return res.status(401).json({ ok: false, error: 'revoked' });
    if (!r.rows[0].perm && r.rows[0].session_token !== payload.st) return res.status(401).json({ ok: false, error: 'revoked' });
    res.json({ ok: true, username: r.rows[0].username, protocol: !!r.rows[0].protocol });
  } catch (e) { console.error('verify error', e); res.status(500).json({ ok: false }); }
});

/* ---------------- Boot ---------------- */
(async () => {
  await initDb();
  app.listen(PORT, () => console.log('Login API listening on ' + PORT));
  await client.login(DISCORD_TOKEN);
  await registerCommands();
  startTrackerLoop();
})().catch((e) => { console.error('fatal boot error', e); process.exit(1); });
