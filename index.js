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
  UserSelectMenuBuilder, ChannelSelectMenuBuilder
} = require('discord.js');

const {
  DISCORD_TOKEN, CLIENT_ID, GUILD_ID, WHITELIST_ROLE_ID,
  JWT_SECRET, DATABASE_URL, ALLOWED_ORIGIN
} = process.env;
const PORT = process.env.PORT || 3000;
const RESET_COOLDOWN_DAYS = Number(process.env.RESET_COOLDOWN_DAYS || 4);
const ANNOUNCE_CHANNEL_ID = process.env.ANNOUNCE_CHANNEL_ID || '';
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
    discord_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    session_token TEXT, created_at TIMESTAMPTZ DEFAULT now(), last_reset_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS perm BOOLEAN DEFAULT false`);
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
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

/* one admin command only â everything else is buttons */
const commands = [
  new SlashCommandBuilder().setName('adminpanel').setDescription('Open the Everlong admin control panel')
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
    .setAuthor({ name: 'EVERLONG Â· MEMBER ACCESS' })
    .setThumbnail(SITE_ICON)
    .setTitle('Your key to the system')
    .setDescription('Purchased access? Set up your private login below.\n\n> Requires the **Whitelisted** role â granted after purchase.')
    .addFields(
      { name: 'ð Create', value: 'Set your password & get your login.', inline: true },
      { name: 'â»ï¸ Reset', value: 'New device Â· every ' + RESET_COOLDOWN_DAYS + 'd.', inline: true },
      { name: 'ð Status', value: 'Check your account.', inline: true }
    )
    .setFooter({ text: 'everlongsguide.netlify.app Â· your password is shown once' });
}
function accessButtons() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('el_create').setLabel('Create account').setEmoji('\uD83D\uDD11').setStyle(ButtonStyle.Success),
    new ButtonBuilder().setCustomId('el_reset').setLabel('Reset password').setEmoji('\u267B\uFE0F').setStyle(ButtonStyle.Secondary),
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
  try { await i.user.send(body); await i.reply({ content: '\u2705 Done \u2014 your username is `' + username + '`. Sent to your DMs.', ephemeral: true }); }
  catch (e) { await i.reply({ content: body + '\n\n*(Couldn\u2019t DM you \u2014 shown privately. Turn on DMs.)*', ephemeral: true }); }
}

/* ----- admin control panel ----- */
function adminPanel() {
  const emb = new EmbedBuilder()
    .setColor(ACCENT)
    .setAuthor({ name: 'EVERLONG Â· ADMIN' })
    .setThumbnail(SITE_ICON)
    .setTitle('Control Panel')
    .setDescription('Everything you need, one tap away.')
    .addFields(
      { name: 'ð¤ Members', value: 'Whitelist Â· Ban Â· Unban Â· Cooldown Â· Force-unlock', inline: false },
      { name: 'ðï¸ Accounts', value: 'Perm account Â· Lookup Â· Wipe Â· Stats Â· Logins', inline: false },
      { name: 'ð£ Content', value: 'Announce Â· Set channel Â· Access / Ticket / Suggestion panels', inline: false },
      { name: 'ð ï¸ Channel', value: 'Lock Â· Unlock Â· Slowmode Â· Purge', inline: false }
    )
    .setFooter({ text: 'Administrators only' });
  const row1 = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('adm_whitelist').setLabel('Whitelist').setEmoji('â').setStyle(ButtonStyle.Success),
    new ButtonBuilder().setCustomId('adm_ban').setLabel('Ban').setEmoji('ð¨').setStyle(ButtonStyle.Danger),
    new ButtonBuilder().setCustomId('adm_unban').setLabel('Unban').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_cooldown').setLabel('Cooldown').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_forceunlock').setLabel('Force-unlock').setStyle(ButtonStyle.Secondary)
  );
  const row2 = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('adm_perm').setLabel('Perm account').setEmoji('ðï¸').setStyle(ButtonStyle.Primary),
    new ButtonBuilder().setCustomId('adm_lookup').setLabel('Lookup').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_wipe').setLabel('Wipe').setStyle(ButtonStyle.Danger),
    new ButtonBuilder().setCustomId('adm_stats').setLabel('Stats').setEmoji('ð').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_logins').setLabel('Logins').setStyle(ButtonStyle.Secondary)
  );
  const row3 = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('adm_announce').setLabel('Announce').setEmoji('ð£').setStyle(ButtonStyle.Primary),
    new ButtonBuilder().setCustomId('adm_setchannel').setLabel('Set channel').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_postaccess').setLabel('Access panel').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_postticket').setLabel('Ticket panel').setEmoji('ð').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_postsuggest').setLabel('Suggestions').setEmoji('ð¡').setStyle(ButtonStyle.Secondary)
  );
  const row4 = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('adm_lock').setLabel('Lock').setEmoji('ð').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_unlock').setLabel('Unlock').setEmoji('ð').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_slowmode').setLabel('Slowmode').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_purge').setLabel('Purge').setEmoji('ð§¹').setStyle(ButtonStyle.Danger)
  );
  return { embeds: [emb], components: [row1, row2, row3, row4] };
}
function userPicker(id, ph) { return new ActionRowBuilder().addComponents(new UserSelectMenuBuilder().setCustomId(id).setPlaceholder(ph).setMinValues(1).setMaxValues(1)); }
function channelPicker(id, ph) { return new ActionRowBuilder().addComponents(new ChannelSelectMenuBuilder().setCustomId(id).setPlaceholder(ph).addChannelTypes(ChannelType.GuildText).setMinValues(1).setMaxValues(1)); }

/* ----- suggestions board ----- */
function suggestPanel() {
  return {
    embeds: [new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG' }).setTitle('Suggestions')
      .setDescription('Got an idea? Submit it below \u2014 everyone can vote with \uD83D\uDC4D / \uD83D\uDC4E.')],
    components: [new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId('sug_open').setLabel('Make a suggestion').setEmoji('\uD83D\uDCA1').setStyle(ButtonStyle.Primary))]
  };
}
function suggestionMessage(id, username, text, up, down) {
  const score = up - down;
  return {
    embeds: [new EmbedBuilder().setColor(ACCENT).setAuthor({ name: '\uD83D\uDCA1 Suggestion' }).setDescription(text)
      .addFields({ name: 'Score', value: '\uD83D\uDC4D ' + up + '\u2003\uD83D\uDC4E ' + down + '\u2003(' + (score >= 0 ? '+' : '') + score + ')' })
      .setFooter({ text: '#' + id + ' \u00b7 by ' + username })],
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
    await ch.send({ embeds: [new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG \u00b7 Update' }).setDescription(msg).setTimestamp(new Date())] });
    return 'posted to <#' + chId + '> and the website';
  } catch (e) { return 'saved to the website (couldn\u2019t post to the channel \u2014 check ID/permissions)'; }
}

async function adminStats(i) {
  const a = (await pool.query("SELECT count(*)::int total, count(*) filter (where session_token is not null)::int active, count(*) filter (where banned)::int banned, count(*) filter (where perm)::int perm FROM accounts")).rows[0];
  const today = (await pool.query("SELECT count(*) filter (where success)::int ok, count(*) filter (where not success)::int fail FROM login_log WHERE created_at > now() - interval '24 hours'")).rows[0];
  const sug = (await pool.query('SELECT count(*)::int c FROM suggestions')).rows[0];
  const emb = new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG \u00b7 STATS' }).setThumbnail(SITE_ICON).setTitle('At a glance')
    .addFields(
      { name: '\uD83D\uDC65 Accounts', value: String(a.total), inline: true },
      { name: '\uD83D\uDFE2 Logged in now', value: String(a.active), inline: true },
      { name: '\uD83D\uDDDD\uFE0F Permanent', value: String(a.perm), inline: true },
      { name: '\uD83D\uDD28 Banned', value: String(a.banned), inline: true },
      { name: '\uD83D\uDD11 Logins (24h)', value: today.ok + ' ok \u00b7 ' + today.fail + ' failed', inline: true },
      { name: '\uD83D\uDCA1 Suggestions', value: String(sug.c), inline: true }
    ).setTimestamp(new Date());
  return i.reply({ embeds: [emb], ephemeral: true });
}

async function adminLogins(i) {
  const r = await pool.query('SELECT username, ip, success, created_at FROM login_log ORDER BY created_at DESC LIMIT 10');
  if (!r.rowCount) return i.reply({ content: 'No login attempts logged yet.', ephemeral: true });
  const lines = r.rows.map(x => (x.success ? '\u2705' : '\u274C') + ' `' + (x.username || '?') + '` \u2014 <t:' + Math.floor(new Date(x.created_at).getTime() / 1000) + ':R>');
  const emb = new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG \u00b7 RECENT LOGINS' }).setDescription(lines.join('\n')).setFooter({ text: 'Last 10 attempts' });
  return i.reply({ embeds: [emb], ephemeral: true });
}

/* ---------------- Interactions ---------------- */
client.on('interactionCreate', async (i) => {
  try {
    /* ===== /adminpanel ===== */
    if (i.isChatInputCommand() && i.commandName === 'adminpanel') {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      return i.reply(Object.assign({ ephemeral: true }, adminPanel()));
    }

    /* ===== admin buttons ===== */
    if (i.isButton() && i.customId.startsWith('adm_')) {
      if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
      switch (i.customId) {
        case 'adm_whitelist': return i.reply({ content: 'Pick a member to **whitelist**:', components: [userPicker('adm_pick_whitelist', 'Member to whitelist')], ephemeral: true });
        case 'adm_ban': return i.reply({ content: 'Pick a member to **ban** (also revokes site access):', components: [userPicker('adm_pick_ban', 'Member to ban')], ephemeral: true });
        case 'adm_cooldown': return i.reply({ content: 'Pick a member to **clear reset cooldown**:', components: [userPicker('adm_pick_cooldown', 'Member')], ephemeral: true });
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
        case 'adm_lookup':
          return i.reply({ content: 'Pick a member to **look up**:', components: [userPicker('adm_pick_lookup', 'Member')], ephemeral: true });
        case 'adm_wipe':
          return i.reply({ content: '\u26A0\uFE0F Pick a member whose account you want to **permanently delete**:', components: [userPicker('adm_pick_wipe', 'Member to wipe')], ephemeral: true });
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
        try { await m.roles.add(WHITELIST_ROLE_ID); } catch (e) { return i.update({ content: 'Couldn\u2019t add the role \u2014 my role must be **above** Whitelisted and I need **Manage Roles**.', components: [] }); }
        return i.update({ content: '\u2705 Whitelisted <@' + uid + '>.', components: [] });
      }
      if (i.customId === 'adm_pick_ban') {
        if (uid === i.user.id) return i.update({ content: 'You can\u2019t ban yourself.', components: [] });
        if (uid === client.user.id) return i.update({ content: 'I can\u2019t ban myself.', components: [] });
        const m = await i.guild.members.fetch(uid).catch(() => null);
        if (m && (m.permissions.has(PermissionFlagsBits.ManageGuild) || m.permissions.has(PermissionFlagsBits.Administrator)))
          return i.update({ content: 'That user is staff \u2014 I won\u2019t ban them.', components: [] });
        const notes = await doBan(i.guild, uid, 'Banned via admin panel');
        return i.update({ content: '\uD83D\uDD28 <@' + uid + '>: ' + notes.join(' \u00b7 ') + '.', components: [] });
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
      if (i.customId === 'adm_pick_lookup') {
        const r = await pool.query('SELECT username, banned, perm, session_token, created_at, last_login_at, last_reset_at FROM accounts WHERE discord_id=$1', [uid]);
        if (!r.rowCount) return i.update({ content: 'No account for <@' + uid + '> yet.', components: [] });
        const a = r.rows[0];
        const fmt = (d) => d ? '<t:' + Math.floor(new Date(d).getTime() / 1000) + ':R>' : '\u2014';
        const emb = new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'Account lookup' }).setTitle(a.username)
          .addFields(
            { name: 'Type', value: a.perm ? '\uD83D\uDDDD\uFE0F Permanent' : 'Standard', inline: true },
            { name: 'Status', value: a.banned ? '\uD83D\uDD28 Banned' : '\u2705 Active', inline: true },
            { name: 'Logged in now', value: a.session_token ? 'Yes' : 'No', inline: true },
            { name: 'Created', value: fmt(a.created_at), inline: true },
            { name: 'Last login', value: fmt(a.last_login_at), inline: true },
            { name: 'Last reset', value: fmt(a.last_reset_at), inline: true }
          ).setFooter({ text: 'User ID ' + uid });
        return i.update({ content: '', embeds: [emb], components: [] });
      }
      if (i.customId === 'adm_pick_wipe') {
        const r = await pool.query('DELETE FROM accounts WHERE discord_id=$1 RETURNING username', [uid]);
        if (!r.rowCount) return i.update({ content: 'That user has no account to wipe.', components: [] });
        return i.update({ content: '\uD83D\uDDD1\uFE0F Deleted the account `' + r.rows[0].username + '` for <@' + uid + '>. They can create a fresh one.', components: [] });
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
        catch (e) { return i.update({ content: 'Couldn\u2019t lock it \u2014 I need **Manage Channels** on that channel.', components: [] }); }
      }
      if (i.customId === 'adm_pick_unlock') {
        try { await lockChannel(ch, false); return i.update({ content: '\uD83D\uDD13 <#' + cid + '> unlocked.', components: [] }); }
        catch (e) { return i.update({ content: 'Couldn\u2019t unlock it \u2014 I need **Manage Channels** on that channel.', components: [] }); }
      }
      return;
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
        } catch (e) { console.error('ticket create', e); return i.reply({ content: 'Couldn\u2019t open a ticket \u2014 I need **Manage Channels**.', ephemeral: true }); }
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
        try { await i.guild.bans.remove(uid); note += ' \u00b7 unbanned from server'; } catch (e) { note += ' \u00b7 (was not server-banned)'; }
        return i.reply({ content: '\u2705 <@' + uid + '>: ' + note + '.', ephemeral: true });
      }
      // admin: create permanent account
      if (i.customId === 'adm_perm_modal') {
        if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
        const u = i.fields.getTextInputValue('u').trim();
        const p = i.fields.getTextInputValue('p');
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(u)) return i.reply({ content: 'Username must be 3\u201320 chars: letters, numbers, underscores.', ephemeral: true });
        const bad = pwError(p); if (bad) return i.reply({ content: bad, ephemeral: true });
        const taken = (await pool.query('SELECT 1 FROM accounts WHERE lower(username)=lower($1)', [u])).rowCount;
        if (taken) return i.reply({ content: 'That username is already taken \u2014 pick another.', ephemeral: true });
        const hash = await bcrypt.hash(p, 10);
        const did = 'perm-' + crypto.randomBytes(8).toString('hex');
        await pool.query('INSERT INTO accounts(discord_id, username, password_hash, session_token, last_reset_at, perm) VALUES ($1,$2,$3,NULL,now(),true)', [did, u, hash]);
        const emb = new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG \u00b7 PERMANENT ACCOUNT' }).setThumbnail(SITE_ICON)
          .setTitle('Account ready')
          .setDescription('Log in and out as much as you want \u2014 **no single-use lock, no cooldown**, multiple devices fine.')
          .addFields(
            { name: 'Username', value: '`' + u + '`', inline: true },
            { name: 'Password', value: '`' + p + '`', inline: true },
            { name: 'Login', value: 'everlongsguide.netlify.app', inline: false }
          ).setFooter({ text: 'Save these \u2014 shown once here.' });
        return i.reply({ embeds: [emb], ephemeral: true });
      }
      // admin: slowmode (this channel)
      if (i.customId === 'adm_slowmode_modal') {
        if (!isAdmin(i)) return i.reply({ content: 'Administrators only.', ephemeral: true });
        let s = parseInt(i.fields.getTextInputValue('s').trim(), 10);
        if (!Number.isFinite(s) || s < 0 || s > 21600) return i.reply({ content: 'Enter a number of seconds between 0 and 21600.', ephemeral: true });
        try { await i.channel.setRateLimitPerUser(s); }
        catch (e) { return i.reply({ content: 'Couldn\u2019t set slowmode \u2014 I need **Manage Channels** here.', ephemeral: true }); }
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
        } catch (e) { return i.reply({ content: 'Couldn\u2019t purge \u2014 I need **Manage Messages** here.', ephemeral: true }); }
      }
      // member: create / reset
      if (i.customId === 'el_create_modal' || i.customId === 'el_reset_modal') {
        if (!hasWhitelist(i.member)) return i.reply({ content: 'You need the **Whitelisted** role.', ephemeral: true });
        const pw = i.fields.getTextInputValue('pw'), pw2 = i.fields.getTextInputValue('pw2');
        if (pw !== pw2) return i.reply({ content: 'Those passwords didn\u2019t match \u2014 try the button again.', ephemeral: true });
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
    if (i.isRepliable()) { try { await i.reply({ content: 'Something went wrong \u2014 try again.', ephemeral: true }); } catch (_) {} }
  }
});

client.once('ready', () => console.log('Discord bot online as ' + client.user.tag));

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
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many attempts â wait a minute.' });
  const username = (req.body && req.body.username || '').toString().toLowerCase().trim();
  const password = (req.body && req.body.password || '').toString();
  if (!username || !password) return res.status(400).json({ error: 'Enter a username and password.' });
  const r = await pool.query('SELECT * FROM accounts WHERE username=$1', [username]);
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
  const token = jwt.sign({ sub: row.discord_id, u: row.username, st: sid }, JWT_SECRET, { expiresIn: '60d' });
  res.json({ token, username: row.username });
});
app.get('/api/verify', async (req, res) => {
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  let payload;
  try { payload = jwt.verify(auth, JWT_SECRET); } catch (e) { return res.status(401).json({ ok: false, error: 'expired' }); }
  try {
    const r = await pool.query('SELECT session_token, username, banned, perm FROM accounts WHERE discord_id=$1', [payload.sub]);
    if (!r.rowCount || r.rows[0].banned) return res.status(401).json({ ok: false, error: 'revoked' });
    if (!r.rows[0].perm && r.rows[0].session_token !== payload.st) return res.status(401).json({ ok: false, error: 'revoked' });
    res.json({ ok: true, username: r.rows[0].username });
  } catch (e) { console.error('verify error', e); res.status(500).json({ ok: false }); }
});

/* ---------------- Boot ---------------- */
(async () => {
  await initDb();
  app.listen(PORT, () => console.log('Login API listening on ' + PORT));
  await client.login(DISCORD_TOKEN);
  await registerCommands();
})().catch((e) => { console.error('fatal boot error', e); process.exit(1); });
