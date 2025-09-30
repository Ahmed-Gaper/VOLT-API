## VOLT API

Node.js/Express TypeScript API with JWT authentication, MongoDB via Mongoose, and basic user management.

### Getting Started

1) Prerequisites
- Node.js 18+
- MongoDB connection string

2) Install dependencies
```bash
npm install
```

3) Configure environment
- Copy `config.env.example` to `config.env` in the project root
- Fill in values:
  - `DATABASE_URL`, `DB_NAME`
  - `JWT_SECRET`, `JWT_EXPIRES_IN`
  - `JWT_REFRESH_SECRET`, `JWT_REFRESH_EXPIRES_IN`
  - `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USERNAME`, `EMAIL_PASSWORD`
  - `PORT` (optional, defaults to 3000 via config)

4) Run in development
```bash
npm run start:dev
```
Server will start and log the health URL: `http://localhost:<PORT>/api/health`.

5) Build for production
```bash
npm run build
```
Outputs compiled files to `dist/`.

### NPM Scripts
- `start:dev`: Run the server with live reload (tsx)
- `build`: Type-check and compile to `dist`
- `typecheck`: TypeScript type checking
- `lint` / `lint:fix`: ESLint checks and auto-fixes
- `format` / `format:fix`: Prettier checks and formatting
- `clean`: Remove `dist`

### Configuration
The app loads `config.env` from the project root via `src/config/config.ts`. Key values:
- `PORT`: Server port
- `NODE_ENV`: `development` or `production`
- `DATABASE_URL`: MongoDB connection string (base + query)
- `DB_NAME`: Database name appended by the app
- `JWT_SECRET`, `JWT_EXPIRES_IN`: Access token secret and duration
- `JWT_REFRESH_SECRET`, `JWT_REFRESH_EXPIRES_IN`: Refresh token secret and duration
- `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USERNAME`, `EMAIL_PASSWORD`: SMTP settings

### Project Structure
```
src/
  app.ts                 Express app, routes, middleware
  server.ts              Entrypoint
  config/
    config.ts            Environment configuration
    database.ts          Mongoose connection
  controllers/           Route handlers
  middleware/            Auth middleware
  models/                Mongoose models
  routes/                Route definitions
  utils/                 Utilities (email)
```

