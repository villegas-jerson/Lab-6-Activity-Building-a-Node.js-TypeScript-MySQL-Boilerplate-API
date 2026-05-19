import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import config from '../config.json';
import db from '../_helpers/db';

export function authorize(roles: string | string[] = []) {
  if (typeof roles === 'string') {
    roles = [roles];
  }

  return [
    // Authenticate JWT token
    (req: Request, res: Response, next: NextFunction) => {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      try {
        const decoded: any = jwt.verify(token, config.secret);
        (req as any).user = { id: decoded.id };
        next();
      } catch {
        return res.status(401).json({ message: 'Unauthorized' });
      }
    },

    // Authorize role
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const account = await db.Account.findByPk((req as any).user.id);

        if (!account || (roles.length && !(roles as string[]).includes(account.role))) {
          return res.status(401).json({ message: 'Unauthorized' });
        }

        // Attach role and ownsToken helper
        (req as any).user.role = account.role;
        
        // 👈 SAFELY CHECK REFRESHTOKENS: Prevent crashing if the array doesn't exist
        (req as any).user.ownsToken = (token: string) => {
          if (!account.refreshTokens) return false;
          return !!account.refreshTokens.find((x: any) => x.token === token);
        };

        next();
      } catch (err) {
        // Log the actual error to Render console before letting Express display a 500 error page
        console.error("Error inside authorize middleware:", err);
        next(err);
      }
    }
  ];
}