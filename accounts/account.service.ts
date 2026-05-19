import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Op } from 'sequelize';
import config from '../config.json';
import db from '../_helpers/db';
import { Role } from '../_helpers/role';
import { sendEmail } from '../_helpers/send-email';

export const accountService = {
  authenticate,
  refreshToken,
  revokeToken,
  register,
  verifyEmail,
  forgotPassword,
  validateResetToken,
  resetPassword,
  getAll,
  getById,
  create,
  update,
  delete: _delete
};

// ─── Auth ──────────────────────────────────────────────

async function authenticate({ email, password, ipAddress }: any) {
  const account = await db.Account.scope('withHash').findOne({ where: { email } });

  if (!account || !account.isVerified || !bcrypt.compareSync(password, account.passwordHash)) {
    throw new Error('Email or password is incorrect'); // 👈 Fixed: Standard Error object
  }

  const jwtToken = generateJwtToken(account);
  const refreshTokenObj = await generateRefreshToken(account, ipAddress);
  await refreshTokenObj.save();

  return { ...basicDetails(account), jwtToken, refreshToken: refreshTokenObj.token };
}

async function refreshToken({ token, ipAddress }: any) {
  const refreshTokenObj = await getRefreshToken(token);
  const account = await refreshTokenObj.getAccount();

  // Rotate refresh token
  const newRefreshToken = await generateRefreshToken(account, ipAddress);
  refreshTokenObj.revoked = new Date();
  refreshTokenObj.revokedByIp = ipAddress;
  refreshTokenObj.replacedByToken = newRefreshToken.token;
  await refreshTokenObj.save();
  await newRefreshToken.save();

  const jwtToken = generateJwtToken(account);

  return { ...basicDetails(account), jwtToken, refreshToken: newRefreshToken.token };
}

async function revokeToken({ token, ipAddress }: any) {
  const refreshTokenObj = await getRefreshToken(token);
  refreshTokenObj.revoked = new Date();
  refreshTokenObj.revokedByIp = ipAddress;
  await refreshTokenObj.save();
}

// ─── Registration ──────────────────────────────────────

async function register(params: any, origin: string) {
  // First account gets Admin role
  const isFirstAccount = (await db.Account.count()) === 0;
  params.role = isFirstAccount ? Role.Admin : Role.User;
  params.verificationToken = randomTokenString();
  params.passwordHash = await hash(params.password);
  params.created = new Date();

  await db.Account.create(params);

  await sendVerificationEmail(params, origin);
}

async function verifyEmail({ token }: any) {
  const account = await db.Account.findOne({ where: { verificationToken: token } });

  if (!account) throw new Error('Verification failed'); // 👈 Fixed: Standard Error object

  account.verified = new Date();
  account.verificationToken = null;
  await account.save();
}

// ─── Password Reset ────────────────────────────────────

async function forgotPassword({ email }: any, origin: string) {
  const account = await db.Account.findOne({ where: { email } });

  // Return silently even if email not found to prevent enumeration
  if (!account) return;

  account.resetToken = randomTokenString();
  account.resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
  await account.save();

  await sendPasswordResetEmail(account, origin);
}

async function validateResetToken({ token }: any) {
  const account = await db.Account.findOne({
    where: {
      resetToken: token,
      resetTokenExpires: { [Op.gt]: new Date() }
    }
  });

  if (!account) throw new Error('Invalid token'); // 👈 Fixed: Standard Error object

  return account;
}

async function resetPassword({ token, password }: any) {
  const account = await validateResetToken({ token });

  account.passwordHash = await hash(password);
  account.passwordReset = new Date();
  account.resetToken = null;
  account.resetTokenExpires = null;
  await account.save();
}

// ─── CRUD ──────────────────────────────────────────────

async function getAll() {
  const accounts = await db.Account.findAll();
  return accounts.map(basicDetails);
}

async function getById(id: number) {
  const account = await getAccount(id);
  return basicDetails(account);
}

async function create(params: any) {
  if (await db.Account.findOne({ where: { email: params.email } })) {
    throw new Error(`Email "${params.email}" is already registered`); // 👈 Fixed: Standard Error object
  }

  params.passwordHash = await hash(params.password);
  params.verified = new Date();
  params.created = new Date();

  const account = await db.Account.create(params);
  return basicDetails(account);
}

async function update(id: number, params: any) {
  const account = await getAccount(id);

  if (params.email && account.email !== params.email &&
      await db.Account.findOne({ where: { email: params.email } })) {
    throw new Error(`Email "${params.email}" is already registered`); // 👈 Fixed: Standard Error object
  }

  if (params.password) {
    params.passwordHash = await hash(params.password);
  }

  Object.assign(account, params);
  account.updated = new Date();
  await account.save();

  return basicDetails(account);
}

async function _delete(id: number) {
  const account = await getAccount(id);
  await account.destroy();
}

// ─── Helpers ───────────────────────────────────────────

async function getAccount(id: number) {
  const account = await db.Account.findByPk(id);
  if (!account) throw new Error('Account not found'); // 👈 Fixed: Standard Error object
  return account;
}

async function getRefreshToken(token: string | undefined) {
  // Prevent system crash if the token parameter is empty or evaluates as 'undefined' string
  if (!token || token === 'undefined') {
    throw new Error('Token is missing'); // 👈 Safely catch missing tokens
  }

  const refreshToken = await db.RefreshToken.findOne({ where: { token } });
  if (!refreshToken || !refreshToken.isActive) {
    throw new Error('Invalid token'); // 👈 Fixed: Standard Error object
  }
  return refreshToken;
}

async function hash(password: string) {
  return bcrypt.hash(password, 10);
}

function generateJwtToken(account: any) {
  return jwt.sign({ id: account.id }, config.secret, { expiresIn: '15m' });
}

async function generateRefreshToken(account: any, ipAddress: string) {
  return db.RefreshToken.build({
    accountId: account.id,
    token: randomTokenString(),
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    createdByIp: ipAddress
  });
}

function randomTokenString() {
  return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account: any) {
  const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;
  return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}

async function sendVerificationEmail(account: any, origin: string) {
  const verifyUrl = `${origin}/#/account/verify-email?token=${account.verificationToken}`;
  await sendEmail({
    to: account.email,
    subject: 'Sign-up Verification - Verify Email',
    html: `
      <h4>Verify Email</h4>
      <p>Thanks for registering!</p>
      <p>Please click the below link to verify your email address:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
    `
  });
}

async function sendPasswordResetEmail(account: any, origin: string) {
  const resetUrl = `${origin}/#/account/reset-password?token=${account.resetToken}`;
  await sendEmail({
    to: account.email,
    subject: 'Sign-up Verification - Reset Password',
    html: `
      <h4>Reset Password Email</h4>
      <p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
    `
  });
}