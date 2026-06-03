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
  await pool.query(`CREATE TABLE IF NOT EXISTS login_log(
    id SERIAL PRIMARY KEY, discord_id TEXT, username TEXT, ip TEXT, success BOOLEAN, created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS announcements(
    id SERIAL PRIMARY KEY, message TEXT NOT NULL, author TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)`);
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
function accessEmbed() {
  return new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG' }).setTitle('Member Access')
    .setDescription('Unlock your access to the Everlong site after your purchase.\n\nOnce you\u2019ve **purchased**, you\u2019ll receive the **Whitelisted** role. Then use the buttons below.\n\u200b')
    .addFields(
      { name: '\uD83D\uDD11  Press "Create account"', value: 'Set your **own password** and get your login. Username is made for you. One per buyer.' },
      { name: '\u267B\uFE0F  Press "Reset password"', value: 'New password / new device. Once every **' + RESET_COOLDOWN_DAYS + ' days**.' },
      { name: '\uD83D\uDD0D  Press "My status"', value: 'See your username, login status, and next reset.' },
      { name: '\u200b', value: '\uD83D\uDED2 **No access yet?** Purchase first \u2014 you can use this once you have the Whitelisted role.' }
    ).setFooter({ text: 'Your password is shown once \u2014 save it.' });
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
  const emb = new EmbedBuilder().setColor(ACCENT).setAuthor({ name: 'EVERLONG' }).setTitle('Admin Control Panel')
    .setDescription('Everything in one place. Buttons only \u2014 no commands.\n\u200b')
    .addFields(
      { name: 'Members', value: '`Whitelist` give access \u00b7 `Ban` ban+revoke \u00b7 `Unban` \u00b7 `Clear cooldown`' },
      { name: 'Content', value: '`Announce` post an update \u00b7 `Set channel` \u00b7 `Post access panel` \u00b7 `Post ticket panel`' },
      { name: 'Channel', value: '`Lock` make a channel view/react-only \u00b7 `Unlock` restore it' }
    ).setFooter({ text: 'Administrators only' });
  const row1 = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('adm_whitelist').setLabel('Whitelist').setEmoji('\u2705').setStyle(ButtonStyle.Success),
    new ButtonBuilder().setCustomId('adm_ban').setLabel('Ban').setEmoji('\uD83D\uDD28').setStyle(ButtonStyle.Danger),
    new ButtonBuilder().setCustomId('adm_unban').setLabel('Unban').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_cooldown').setLabel('Clear cooldown').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_announce').setLabel('Announce').setEmoji('\uD83D\uDCE2').setStyle(ButtonStyle.Primary)
  );
  const row2 = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('adm_setchannel').setLabel('Set channel').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_postaccess').setLabel('Post access panel').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_postticket').setLabel('Post ticket panel').setEmoji('\uD83D\uDED2').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_lock').setLabel('Lock').setEmoji('\uD83D\uDD12').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId('adm_unlock').setLabel('Unlock').setEmoji('\uD83D\uDD13').setStyle(ButtonStyle.Secondary)
  );
  return { embeds: [emb], components: [row1, row2] };
}
function userPicker(id, ph) { return new ActionRowBuilder().addComponents(new UserSelectMenuBuilder().setCustomId(id).setPlaceholder(ph).setMinValues(1).setMaxValues(1)); }
function channelPicker(id, ph) { return new ActionRowBuilder().addComponents(new ChannelSelectMenuBuilder().setCustomId(id).setPlaceholder(ph).addChannelTypes(ChannelType.GuildText).setMinValues(1).setMaxValues(1)); }

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
  if (row.session_token) return res.status(409).json({ error: 'This account is already in use. Reset it in the Everlong Discord to log in again.' });
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
    const r = await pool.query('SELECT session_token, username, banned FROM accounts WHERE discord_id=$1', [payload.sub]);
    if (!r.rowCount || r.rows[0].banned || r.rows[0].session_token !== payload.st) return res.status(401).json({ ok: false, error: 'revoked' });
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
