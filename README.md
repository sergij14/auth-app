# Auth App

## Stack
- **Runtime**: Node.js
- **Framework**: Express v5
- **Database**: NeDB (embedded NoSQL)
- **Authentication**: JWT (jsonwebtoken)
- **Password Hashing**: bcryptjs

## Architecture
```
├── config/          # JWT secrets & token expiration
├── db/              # NeDB datastore instances
├── middlewares/     # isAuthenticated, isAuthorized
├── routes/          # auth, user, role endpoints
└── utils/           # JWT token generators
```

## API Endpoints

### Auth (`/api/auth`)
- `POST /register` - Create user (email, password, role)
- `POST /login` - Returns access + refresh tokens
- `POST /refresh-token` - Generate new access token
- `POST /logout` - Invalidate access token

### User (`/api/user`)
- `GET /current` - Get authenticated user info

### Role (`/api/role`)
- `GET /admin` - Admin-only route
- `GET /moderator` - Admin & moderator route

## Token Management
- **Access Token**: 30s expiry, HS256 signed
- **Refresh Token**: 2m expiry, stored in DB
- **Invalid Tokens**: Blacklist for logged out tokens
- **Authorization**: `Bearer <token>` in headers

## Database Collections
- `Users.db` - User credentials & roles
- `Users.RefreshTokens.db` - Active refresh tokens
- `Users.InvalidTokens.db` - Blacklisted tokens

## Setup
```bash
npm install
npm run dev    # Development with nodemon
npm start      # Production
```

Server runs on `http://localhost:3000`
