import express, { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { accountService } from './account.service';
import { authorize } from '../_middleware/authorize';
import { validateRequest } from '../_middleware/validate-request';
import { Role } from '../_helpers/role';

const router = express.Router();

// ─── Routes ────────────────────────────────────────────

router.post('/authenticate', authenticateSchema, authenticate);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', authorize() as any, revokeTokenSchema, revokeToken);
router.post('/register', registerSchema, register);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post('/validate-reset-token', validateResetTokenSchema, validateResetToken);
router.post('/reset-password', resetPasswordSchema, resetPassword);
router.get('/', authorize(Role.Admin) as any, getAll);
router.get('/:id', authorize() as any, getById);
router.post('/', authorize(Role.Admin) as any, createSchema, create);
router.put('/:id', authorize() as any, updateSchema, update);
router.delete('/:id', authorize() as any, _delete);

export default router;

// ─── Schema Validation Middleware ──────────────────────

function authenticateSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required()
  });
  validateRequest(req, next, schema);
}

function revokeTokenSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({ token: Joi.string().empty('') });
  validateRequest(req, next, schema);
}

function registerSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    title: Joi.string(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
    acceptTerms: Joi.boolean().valid(true).required()
  });
  validateRequest(req, next, schema);
}

function verifyEmailSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({ token: Joi.string().required() });
  validateRequest(req, next, schema);
}

function forgotPasswordSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({ email: Joi.string().email().required() });
  validateRequest(req, next, schema);
}

function validateResetTokenSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({ token: Joi.string().required() });
  validateRequest(req, next, schema);
}

function resetPasswordSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required()
  });
  validateRequest(req, next, schema);
}

function createSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    title: Joi.string(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
    role: Joi.string().valid(Role.Admin, Role.User).required()
  });
  validateRequest(req, next, schema);
}

function updateSchema(req: Request, res: Response, next: NextFunction) {
  const schemaRules: any = {
    title: Joi.string(),
    firstName: Joi.string().empty(''),
    lastName: Joi.string().empty(''),
    email: Joi.string().email().empty(''),
    password: Joi.string().min(6).empty(''),
    confirmPassword: Joi.string().valid(Joi.ref('password')).empty('')
  };
  if ((req as any).user?.role === Role.Admin) {
    schemaRules.role = Joi.string().valid(Role.Admin, Role.User).empty('');
  }
  validateRequest(req, next, Joi.object(schemaRules));
}

// ─── Route Handlers ────────────────────────────────────

function authenticate(req: Request, res: Response, next: NextFunction) {
  const { email, password } = req.body;
  const ipAddress = req.ip;
  accountService.authenticate({ email, password, ipAddress })
    .then(({ refreshToken, ...account }) => {
      setTokenCookie(res, refreshToken);
      res.json(account);
    })
    .catch(next);
}

function refreshToken(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.refreshToken;
  const ipAddress = req.ip;
  accountService.refreshToken({ token, ipAddress })
    .then(({ refreshToken, ...account }) => {
      setTokenCookie(res, refreshToken);
      res.json(account);
    })
    .catch(next);
}

function revokeToken(req: Request, res: Response, next: NextFunction) {
  const token = req.body.token || req.cookies.refreshToken;
  const ipAddress = req.ip;

  if (!token) return res.status(400).json({ message: 'Token is required' });

  const user = (req as any).user;
  if (user.role !== Role.Admin && !user.ownsToken(token)) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  accountService.revokeToken({ token, ipAddress })
    .then(() => res.json({ message: 'Token revoked' }))
    .catch(next);
}

function register(req: Request, res: Response, next: NextFunction) {
  // ✅ Hardcoded to Angular frontend URL so verification email links work correctly
  const origin = 'https://villegas-lab7-activity.vercel.app';
  accountService.register(req.body, origin)
    .then(() => res.json({ message: 'Registration successful, please check your email for verification instructions' }))
    .catch(next);
}

function verifyEmail(req: Request, res: Response, next: NextFunction) {
  accountService.verifyEmail(req.body)
    .then(() => res.json({ message: 'Verification successful, you can now login' }))
    .catch(next);
}

function forgotPassword(req: Request, res: Response, next: NextFunction) {
  const origin = 'https://villegas-lab7-activity.vercel.app';
  accountService.forgotPassword(req.body, origin)
    .then(() => res.json({ message: 'Please check your email for password reset instructions' }))
    .catch(next);
}

function validateResetToken(req: Request, res: Response, next: NextFunction) {
  accountService.validateResetToken(req.body)
    .then(() => res.json({ message: 'Token is valid' }))
    .catch(next);
}

function resetPassword(req: Request, res: Response, next: NextFunction) {
  accountService.resetPassword(req.body)
    .then(() => res.json({ message: 'Password reset successful, you can now login' }))
    .catch(next);
}

function getAll(req: Request, res: Response, next: NextFunction) {
  accountService.getAll()
    .then(accounts => res.json(accounts))
    .catch(next);
}

function getById(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;
  const id = parseInt(req.params.id as string);
  if (id !== user.id && user.role !== Role.Admin) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  accountService.getById(id as any)
    .then(account => account ? res.json(account) : res.sendStatus(404))
    .catch(next);
}

function create(req: Request, res: Response, next: NextFunction) {
  accountService.create(req.body)
    .then(account => res.json(account))
    .catch(next);
}

function update(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;
  const id = parseInt(req.params.id as string);
  if (id !== user.id && user.role !== Role.Admin) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  accountService.update(id, req.body)
    .then(account => res.json(account))
    .catch(next);
}

function _delete(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;
  const id = parseInt(req.params.id as string);
  if (id !== user.id && user.role !== Role.Admin) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  accountService.delete(id)
    .then(() => res.json({ message: 'Account deleted successfully' }))
    .catch(next);
}

// ─── Cookie Helper ─────────────────────────────────────

function setTokenCookie(res: Response, token: string) {
  const cookieOptions = {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    sameSite: 'lax' as const  // ✅ fixed: allows cookie to be sent with cross-origin requests
  };
  res.cookie('refreshToken', token, cookieOptions);
}