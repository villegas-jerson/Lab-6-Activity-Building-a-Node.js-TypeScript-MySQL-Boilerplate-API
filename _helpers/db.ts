import { Sequelize } from 'sequelize';
import mysql2 from 'mysql2/promise';
import config from '../config.json';
import { accountModel } from '../accounts/account.model';
import { refreshTokenModel } from '../accounts/refresh-token.model';

const db: any = {};

export async function initialize() {
  // Use environment variables if they exist (on Render), otherwise fall back to config.json (locally)
  const host = process.env.DB_HOST || config.database.host;
  const port = Number(process.env.DB_PORT) || config.database.port;
  const user = process.env.DB_USER || config.database.user;
  const password = process.env.DB_PASSWORD || config.database.password;
  const database = process.env.DB_NAME || config.database.database;

  // Create DB if not exists 
  // Note: Hostinger usually doesn't allow creating databases via code, 
  // but keeping this block safe with a try/catch prevents it from crashing your app.
  try {
    const connection = await mysql2.createConnection({ host, port, user, password });
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${database}\`;`);
    await connection.end();
  } catch (err) {
    console.log("Database check/creation skipped or handled by host provider.");
  }

  // Connect with Sequelize
  const sequelize = new Sequelize(database, user, password, {
    host,
    port,
    dialect: 'mysql',
    logging: false
  });

  // Init models
  db.Account = accountModel(sequelize);
  db.RefreshToken = refreshTokenModel(sequelize);

  // Relationships
  db.Account.hasMany(db.RefreshToken, { onDelete: 'CASCADE' });
  db.RefreshToken.belongsTo(db.Account);

  
  await sequelize.sync({ alter: true });

  db.sequelize = sequelize;
}

export default db;